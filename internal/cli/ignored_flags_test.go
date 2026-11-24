package cli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// #95: a flag value the chosen mode or command would silently ignore is a
// usage error (exit 2), caught before anything is started, stopped or pushed.
func TestIgnoredFlagsAreUsageErrors(t *testing.T) {
	root := lifecycleTemplates(t, nil, "foo")
	runArgs := func(extra ...string) []string {
		return append([]string{"-T", root, "run", "-t", "foo", "-detach", "-no-verify", "-ready-timeout", "1s", "-nuclei-templates", t.TempDir()}, extra...)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"host-port-map key not published", runArgs("-expose", "host", "-host-port-map", "9999=39999"),
			"-host-port-map 9999=39999: foo does not publish container port 9999 (it publishes 8080)"},
		{"bind outside host mode", runArgs("-bind", "0.0.0.0"), "-bind is used only by -expose host (the mode is internal)"},
		{"bind with macvlan", runArgs("-expose", "macvlan", "-parent", "eth0", "-bind", "0.0.0.0"), "-bind is used only by -expose host (the mode is macvlan)"},
		{"parent outside macvlan", runArgs("-expose", "host", "-parent", "eth0"), "-parent is used only by -expose macvlan (the mode is host)"},
		{"ip outside macvlan", runArgs("-ip", "192.168.1.50"), "-ip is used only by -expose macvlan"},
		{"subnet outside macvlan", runArgs("-subnet", "192.168.1.0/24"), "-subnet is used only by -expose macvlan"},
		{"gateway outside macvlan", runArgs("-gateway", "192.168.1.1"), "-gateway is used only by -expose macvlan"},
		{"no-egress with host", runArgs("-expose", "host", "-no-egress"), "-no-egress is used only by -expose internal (the mode is host)"},
		{"no-egress with macvlan", runArgs("-expose", "macvlan", "-parent", "eth0", "-no-egress"), "-no-egress is used only by -expose internal (the mode is macvlan)"},
		{"stop -t with -prune-net", []string{"-T", root, "stop", "-t", "foo", "-prune-net"}, "-prune-net removes the network only when stopping everything"},
		{"stop selector arg with -prune-net", []string{"-T", root, "stop", "foo", "-prune-net"}, "-prune-net removes the network only when stopping everything"},
		{"build -registry without -push", []string{"-T", root, "build", "-t", "foo", "-registry", "ghcr.io/x/y"}, "-registry is only used by -push"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := lifecycleFake(t)
			code, out, errOut := run(t, fe, tc.args...)
			if code != ExitUsage || !strings.Contains(errOut, tc.want) {
				t.Fatalf("exit %d, want %d with %q\nstdout: %s\nstderr: %s", code, ExitUsage, tc.want, out, errOut)
			}
			if len(fe.Containers) != 0 || len(fe.Builds) != 0 || len(fe.Pulls) != 0 {
				t.Fatalf("a usage error must not touch the engine: containers=%d builds=%d pulls=%v", len(fe.Containers), len(fe.Builds), fe.Pulls)
			}
		})
	}

	// The same flags in the mode that uses them still work.
	port := freePort(t)
	fe := lifecycleFake(t)
	code, out, errOut := run(t, fe, runArgs("-expose", "host", "-bind", "127.0.0.1", "-host-port-map", "8080="+strconv.Itoa(port))...)
	if code != ExitOK {
		t.Fatalf("host mode with a published port pinned: %d\n%s\n%s", code, out, errOut)
	}
	if c := fe.Containers[contract.ContainerNamePrefix+"foo-vulnerable"]; c == nil || len(c.Spec.Ports) == 0 || c.Spec.Ports[0].HostPort != port {
		t.Fatalf("pin not applied: %+v", c)
	}
	if code, out, errOut = run(t, fe, "-T", root, "stop", "-prune-net"); code != ExitOK {
		t.Fatalf("stop -prune-net: %d\n%s\n%s", code, out, errOut)
	}
}

// #95: -state vulnerable,vulnerable builds (and would push) each image once.
func TestBuildStateDeduplicated(t *testing.T) {
	root := fixtures(t)
	fe := enginetest.New()
	code, out, errOut := run(t, fe, "-json", "-T", root, "build", "-t", "apache", "-state", "vulnerable,vulnerable", "-push", "-registry", "ghcr.io/ruzfi/vulnsuite")
	var res []buildResult
	if code != ExitOK || json.Unmarshal([]byte(out), &res) != nil {
		t.Fatalf("build: %d\n%s\n%s", code, out, errOut)
	}
	if len(res) != 1 || res[0].State != "vulnerable" {
		t.Fatalf("want one vulnerable job, got %d: %s", len(res), out)
	}
	if got, err := parseStates("patched, vulnerable,patched"); err != nil || strings.Join(got, ",") != "patched,vulnerable" {
		t.Fatalf("parseStates = %v, %v", got, err)
	}
}
