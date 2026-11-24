//go:build linux

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #146: killStep kills the step's whole process tree (a pipeline, a
// background job, a grandchild), with setsid and, through the /proc walk,
// without it.
func TestKillStepScriptKillsProcessTree(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("needs /proc (Linux)")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, setsid := range []bool{true, false} {
		t.Run(fmt.Sprintf("setsid=%v", setsid), func(t *testing.T) {
			if _, err := exec.LookPath("setsid"); setsid && err != nil {
				t.Skip("no setsid")
			}
			dir := t.TempDir()
			pidFile, pids := filepath.Join(dir, "step.pid"), filepath.Join(dir, "pids")
			q := shellQuote(pids)
			// Every process of the tree records its PID, then sleeps.
			rec := fmt.Sprintf(`sh -c 'echo $$ >> %s; exec sleep 300'`, q)
			step := fmt.Sprintf(`%s | %s & (%s & wait) & %s; wait`, rec, rec, rec, rec)
			w := trackStepPID(step, pidFile)
			if !setsid {
				w = strings.Replace(w, "command -v setsid", "command -v no-such-setsid", 1)
			}
			run := exec.Command(sh, "-c", w)
			if err := run.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = run.Wait(); close(done) }()
			var list []string
			for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(20 * time.Millisecond) {
				b, _ := os.ReadFile(pids)
				if list = strings.Fields(string(b)); len(list) == 4 {
					break
				}
			}
			if len(list) != 4 {
				t.Fatalf("the tree did not start: %v", list)
			}
			pf, _ := os.ReadFile(pidFile)
			if got := strings.HasSuffix(strings.TrimSpace(string(pf)), " g"); got != setsid {
				t.Fatalf("PID file %q: group mark %v, want %v", pf, got, setsid)
			}
			if out, err := exec.Command(sh, "-c", killStepScript(pidFile)).CombinedOutput(); err != nil {
				t.Fatalf("kill: %v %s", err, out)
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the step's wrapper did not end")
			}
			for start := time.Now(); ; time.Sleep(20 * time.Millisecond) {
				var alive []string
				for _, p := range list {
					if b, err := os.ReadFile("/proc/" + p + "/status"); err == nil && !strings.Contains(string(b), "\nState:\tZ") {
						alive = append(alive, p)
					}
				}
				if len(alive) == 0 {
					break
				}
				if time.Since(start) > 5*time.Second {
					for _, p := range alive {
						if n, err := strconv.Atoi(p); err == nil {
							_ = syscall.Kill(n, syscall.SIGKILL)
						}
					}
					t.Fatalf("processes of the step survived the kill: %v of %v", alive, list)
				}
			}
		})
	}
}
