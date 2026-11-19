package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

func isHealthcheck(cmd string) bool { return strings.Contains(cmd, "/proc/net/tcp") }

// unreachableRunner is a runner whose targets this machine cannot reach (the
// default internal mode on Docker Desktop/OrbStack, macvlan).
func unreachableRunner(fe *enginetest.Fake) *Runner {
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	return r
}

// When the target is unreachable from here, the healthcheck runs inside it,
// and seeds wait for it instead of racing the service's startup.
func TestUnreachableTargetHealthcheckRunsInsideBeforeSeeds(t *testing.T) {
	var mu sync.Mutex
	var order []string
	upAt := time.Now().Add(1500 * time.Millisecond)
	fe := enginetest.New()
	fe.ExecFn = func(_, cmd string) (int, string, error) {
		mu.Lock()
		defer mu.Unlock()
		if isHealthcheck(cmd) {
			if !strings.Contains(cmd, "p=18EB") { // 6379, the healthcheck's port
				t.Errorf("healthcheck checks the wrong port: %s", cmd)
			}
			if time.Now().Before(upAt) {
				order = append(order, "hc:down")
				return 1, "", nil
			}
			order = append(order, "hc:up")
			return 0, "", nil
		}
		if time.Now().Before(upAt) {
			order = append(order, "seed:early")
			return 1, "ERROR 2002: Can't connect", nil
		}
		order = append(order, "seed")
		return 0, "", nil
	}
	r := unreachableRunner(fe)
	c := load(t, "redis-unauthenticated-access")
	c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "redis-cli set k v"}}
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{ReadyTimeout: 20 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready {
		t.Fatalf("not ready: %s", h.ReadyDetail)
	}
	if len(h.Seeds) != 1 || !h.Seeds[0].OK {
		t.Fatalf("seed raced the service: %+v (execs %v)", h.Seeds, order)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) < 3 || order[0] != "hc:down" || order[len(order)-2] != "hc:up" || order[len(order)-1] != "seed" {
		t.Fatalf("exec order %v; want the healthcheck polled until up, then the seed", order)
	}
}

// A healthcheck that never passes inside the target makes it not ready, and
// its seeds are skipped.
func TestUnreachableTargetHealthcheckTimesOut(t *testing.T) {
	fe := enginetest.New()
	fe.ExecFn = func(_, cmd string) (int, string, error) {
		if isHealthcheck(cmd) {
			return 1, "", nil
		}
		return 0, "", nil
	}
	r := unreachableRunner(fe)
	c := load(t, "redis-unauthenticated-access")
	c.States["vulnerable"].Seed = []contract.SeedStep{{Run: "redis-cli set k v"}}
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{ReadyTimeout: 2 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready || !strings.Contains(h.ReadyDetail, "did not pass within 2s") {
		t.Fatalf("ready=%v detail=%q", h.Ready, h.ReadyDetail)
	}
	if len(h.Seeds) != 1 || !h.Seeds[0].Skipped {
		t.Fatalf("seeds: %+v", h.Seeds)
	}
}

// An image the check cannot run in (no shell) keeps the old answer: ready once
// the container runs.
func TestUnreachableTargetWithoutShellIsReadyWhenRunning(t *testing.T) {
	fe := enginetest.New()
	fe.ExecFn = func(string, string) (int, string, error) {
		return -1, "", errors.New(`OCI runtime exec failed: exec: "sh": executable file not found in $PATH`)
	}
	r := unreachableRunner(fe)
	c := load(t, "redis-unauthenticated-access")
	start := time.Now()
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{ReadyTimeout: 20 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready {
		t.Fatalf("not ready: %s", h.ReadyDetail)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %s", el)
	}
}

// exec probes need no network path, so they run when the target is
// unreachable from here; only the network probes are skipped.
func TestUnreachableTargetRunsExecProbes(t *testing.T) {
	shadow := contract.Probe{Exec: &contract.ExecProbe{Run: "cat /etc/shadow", StdoutMatches: "root:"}}
	tcp := contract.Probe{TCP: &contract.TCPProbe{Port: 6379}}
	for name, tc := range map[string]struct {
		verify  []contract.Probe
		out     string
		want    *bool
		details []string
	}{
		"exec only, passes":    {[]contract.Probe{shadow}, "root:x:0:0", boolp(true), []string{"ok   exec"}},
		"exec only, fails":     {[]contract.Probe{shadow}, "nobody", boolp(false), []string{"FAIL exec"}},
		"mixed, exec passes":   {[]contract.Probe{shadow, tcp}, "root:x:0:0", nil, []string{"ok   exec", "skip 1 network probe(s): could not verify from this host"}},
		"mixed, exec fails":    {[]contract.Probe{tcp, shadow}, "nobody", boolp(false), []string{"FAIL exec", "skip 1 network probe(s)"}},
		"network only skipped": {[]contract.Probe{tcp}, "", nil, []string{"could not verify from this host"}},
	} {
		t.Run(name, func(t *testing.T) {
			fe := enginetest.New()
			fe.ExecFn = func(_, cmd string) (int, string, error) {
				if cmd == "cat /etc/shadow" {
					return 0, tc.out, nil
				}
				return 0, "", nil // the in-container healthcheck
			}
			r := unreachableRunner(fe)
			c := load(t, "redis-unauthenticated-access")
			c.States["vulnerable"].Verify = tc.verify
			h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{Verify: true, Build: builder.Options{Pull: true}})
			if err != nil {
				t.Fatal(err)
			}
			if (h.VerifyOK == nil) != (tc.want == nil) || (h.VerifyOK != nil && *h.VerifyOK != *tc.want) {
				t.Fatalf("VerifyOK = %v, want %v; detail %q", deref(h.VerifyOK), deref(tc.want), h.VerifyDetail)
			}
			for _, d := range tc.details {
				if !strings.Contains(h.VerifyDetail, d) {
					t.Errorf("detail %q lacks %q", h.VerifyDetail, d)
				}
			}
		})
	}
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// The listening check parses /proc/net/tcp{,6} with sh builtins: run it
// against fixture files in a real shell.
func TestListenScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script runs inside Linux containers; Git Bash on Windows cannot read the fixture paths")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tcp4 := header +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n" + // 127.0.0.1:8080 LISTEN
		"   1: 0100007F:18EB 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0\n" // :6379 ESTABLISHED, not listening
	tcp6 := header +
		"   0: 00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0\n" // [::]:3306 LISTEN
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p4, p6 := write("tcp", tcp4), write("tcp6", tcp6)
	run := func(script string) int {
		cmd := exec.Command(sh, "-c", script)
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}
	fixture := func(port int, f4, f6 string) string {
		s := listenScript(port)
		s = strings.ReplaceAll(s, "/proc/net/tcp6", f6)
		return strings.ReplaceAll(s, "/proc/net/tcp", f4)
	}
	for port, want := range map[int]int{8080: insideReady, 3306: insideReady, 6379: insideNotReady, 80: insideNotReady} {
		if got := run(fixture(port, p4, p6)); got != want {
			t.Errorf("port %d: exit %d, want %d", port, got, want)
		}
	}
	missing := filepath.Join(dir, "missing")
	if got := run(fixture(8080, missing, missing+"6")); got != insideCannot {
		t.Errorf("no /proc/net/tcp: exit %d, want %d", got, insideCannot)
	}
	// The http script without curl falls back to the listening check.
	s := httpScript("http", 8080, "/it's", 200)
	if !strings.Contains(s, `'http://127.0.0.1:8080/it'\''s'`) {
		t.Errorf("url not quoted: %s", s)
	}
	s = strings.ReplaceAll(s, "command -v curl", "command -v no-such-curl-binary")
	s = strings.ReplaceAll(strings.ReplaceAll(s, "/proc/net/tcp6", p6), "/proc/net/tcp", p4)
	if got := run(s); got != insideReady {
		t.Errorf("http fallback: exit %d", got)
	}
}

// Finding out that the target is unreachable takes time (two dial timeouts);
// a short -ready-timeout must still leave the in-container check its turn.
func TestUnreachableTargetShortTimeoutStillChecksInside(t *testing.T) {
	fe := enginetest.New()
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach {
		time.Sleep(700 * time.Millisecond)
		return probes.Unreachable
	}
	c := load(t, "redis-unauthenticated-access")
	h, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !h.Ready {
		t.Fatalf("not ready: %s", h.ReadyDetail)
	}
	if len(fe.Execs) == 0 || !isHealthcheck(fe.Execs[0]) {
		t.Fatalf("the in-container healthcheck did not run: %v", fe.Execs)
	}
}
