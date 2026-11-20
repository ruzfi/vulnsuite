package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// sidecarContract is an image-kind target with both states and the given
// sidecars.
func sidecarContract(id string, sidecars ...string) *contract.Contract {
	c := &contract.Contract{
		APIVersion: contract.APIVersion, Kind: "Target",
		Metadata: contract.Metadata{ID: id},
		Base:     contract.Base{Kind: contract.BaseImage, Image: "example/app:1"},
		Service:  contract.Service{Ports: []contract.Port{{Container: 8080, Protocol: "http"}}},
		States: map[string]*contract.State{
			contract.StateVulnerable: {Name: contract.StateVulnerable},
			contract.StatePatched:    {Name: contract.StatePatched, Environment: map[string]string{"MODE": "patched"}},
		},
	}
	for _, sc := range sidecars {
		c.Service.Sidecars = append(c.Service.Sidecars, contract.Sidecar{Name: sc, Image: "example/" + sc + ":1"})
	}
	return c
}

func lifecycleRunner() (*enginetest.Fake, *Runner) {
	fe := enginetest.New()
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	return fe, r
}

var pullOpts = Options{Build: builder.Options{Pull: true}}

func mustRun(t *testing.T, r *Runner, c *contract.Contract, state string, exp Exposure) *Handle {
	t.Helper()
	h, err := r.Run(context.Background(), c, state, exp, pullOpts)
	if err != nil {
		t.Fatalf("run %s %s: %v", c.ID(), state, err)
	}
	return h
}

func containerNames(fe *enginetest.Fake) []string {
	rows, _ := fe.ContainerList(context.Background(), true, "")
	var out []string
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

// #42 item 1: stop -t foo must not stop foo-bar, and both targets and their
// sidecars carry the exact id label it matches on.
func TestStopAllMatchesExactTemplateID(t *testing.T) {
	fe, r := lifecycleRunner()
	foo, fooBar := sidecarContract("foo", "db"), sidecarContract("foo-bar", "db")
	hFoo := mustRun(t, r, foo, "vulnerable", DefaultExposure())
	hBar := mustRun(t, r, fooBar, "vulnerable", DefaultExposure())
	for _, n := range []string{hFoo.Container, hFoo.Sidecars[0]} {
		l := fe.Containers[n].Spec.Labels
		if l[builder.LabelID] != "foo" || l[builder.LabelState] != "vulnerable" || l[LabelManaged] != "true" || l[LabelRole] == "" {
			t.Fatalf("%s labels: %v", n, l)
		}
	}
	removed, err := r.StopAll(context.Background(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != hFoo.Container+","+hFoo.Sidecars[0] {
		t.Fatalf("stop foo removed %v", removed)
	}
	if fe.Containers[hBar.Container] == nil || fe.Containers[hBar.Sidecars[0]] == nil {
		t.Fatalf("stop foo removed foo-bar's containers: %v", containerNames(fe))
	}
	if _, ok := fe.Networks[hFoo.SidecarNetwork]; ok {
		t.Fatal("foo's sidecar network should be removed")
	}
	if _, ok := fe.Networks[hBar.SidecarNetwork]; !ok {
		t.Fatal("foo-bar's sidecar network must stay")
	}
}

// Containers that merely share the prefix but were not started by vulnsuite
// are neither listed nor removed.
func TestFleetIgnoresUnmanagedContainers(t *testing.T) {
	fe, r := lifecycleRunner()
	fe.Containers["vulnsuite-elasticsearch-vulnerable"] = &enginetest.Container{ID: "x1", Running: true,
		Spec: engine.ContainerSpec{Name: "vulnsuite-elasticsearch-vulnerable"}}
	if rows, _ := r.Running(context.Background(), DefaultNetwork); len(rows) != 0 {
		t.Fatalf("unmanaged container listed: %+v", rows)
	}
	if removed, err := r.StopAll(context.Background(), ""); err != nil || len(removed) != 0 {
		t.Fatalf("unmanaged container removed: %v %v", removed, err)
	}
}

// #42 item 2: a sidecar that fails to start must not leave the earlier ones
// (or itself) behind.
func TestSidecarStartFailureCleansUp(t *testing.T) {
	fe, r := lifecycleRunner()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if strings.HasSuffix(spec.Name, "-cache") {
			return errors.New("port already allocated")
		}
		return nil
	}
	c := sidecarContract("leaky", "db", "cache")
	if _, err := r.Run(context.Background(), c, "vulnerable", DefaultExposure(), pullOpts); err == nil || !strings.Contains(err.Error(), "sidecar cache") {
		t.Fatalf("want the sidecar start error, got %v", err)
	}
	if names := containerNames(fe); len(names) != 0 {
		t.Fatalf("leaked containers: %v", names)
	}
	if _, ok := fe.Networks[SidecarNetworkName("leaky", "vulnerable")]; ok {
		t.Fatal("leaked the sidecar network")
	}
}

// #42 item 3: in host and macvlan mode the target resolves its sidecars by
// name, ports are still published, and the reported IP is not the private one.
func TestSidecarsResolvableInEveryMode(t *testing.T) {
	for _, exp := range []Exposure{
		DefaultExposure(),
		{Mode: ModeHost, Bind: "127.0.0.1"},
		{Mode: ModeMacvlan, Parent: "eth0"},
	} {
		t.Run(exp.Mode, func(t *testing.T) {
			fe, r := lifecycleRunner()
			h := mustRun(t, r, sidecarContract("sc-demo", "db"), "vulnerable", exp)
			want := SidecarContainerName("sc-demo", "vulnerable", "db")
			if got := fe.Resolve(h.Container, "db"); len(got) != 1 || got[0] != want {
				t.Fatalf("target resolves db to %v, want [%s]", got, want)
			}
			if got := fe.Resolve(want, "sc-demo"); len(got) != 1 || got[0] != h.Container {
				t.Fatalf("sidecar resolves the target to %v", got)
			}
			scNet := fe.Networks[h.SidecarNetwork]
			spec := fe.Containers[h.Container].Spec
			// The fake's address on the target's first (exposure) network; the
			// sidecar network's are 10.99.x.x.
			primaryIP := fe.Containers[h.Container].IP
			switch exp.Mode {
			case ModeHost:
				if len(spec.Ports) != 1 || spec.Ports[0].HostPort == 0 || h.EndpointHost != "127.0.0.1" {
					t.Fatalf("host mode must still publish: %+v %+v", spec.Ports, h)
				}
				if scNet.Internal {
					t.Fatal("ports cannot be published from an internal network")
				}
			case ModeMacvlan:
				if spec.Network.Name != "vulnsuite-macvlan-eth0" || !scNet.Internal {
					t.Fatalf("macvlan: primary %s, sidecar net internal=%v", spec.Network.Name, scNet.Internal)
				}
				if h.EndpointHost != primaryIP {
					t.Fatalf("macvlan endpoint must be the LAN address %s, got %s", primaryIP, h.EndpointHost)
				}
			case ModeInternal:
				if spec.Network.Name != DefaultNetwork || h.EndpointHost != "sc-demo-vulnerable" {
					t.Fatalf("internal: network %s endpoint %s", spec.Network.Name, h.EndpointHost)
				}
			}
			rows, err := r.Running(context.Background(), DefaultNetwork)
			if err != nil || len(rows) != 1 || rows[0].IP != primaryIP {
				t.Fatalf("ps must show the target once, at its exposure address %s: %v %+v", primaryIP, err, rows)
			}
			if err := r.Stop(context.Background(), h); err != nil {
				t.Fatal(err)
			}
			if names := containerNames(fe); len(names) != 0 {
				t.Fatalf("stop left %v", names)
			}
			if _, ok := fe.Networks[h.SidecarNetwork]; ok {
				t.Fatal("stop left the sidecar network")
			}
		})
	}
}

// #42 item 4: both states of a template run side by side, each with its own
// sidecars, and every name resolves to exactly one container.
func TestStatesAreIsolated(t *testing.T) {
	fe, r := lifecycleRunner()
	c := sidecarContract("sc-demo", "db")
	hv := mustRun(t, r, c, "vulnerable", DefaultExposure())
	vulnDB := fe.Containers[hv.Sidecars[0]].ID
	hp := mustRun(t, r, c, "patched", DefaultExposure())
	if fe.Containers[hv.Sidecars[0]] == nil || fe.Containers[hv.Sidecars[0]].ID != vulnDB {
		t.Fatal("starting patched replaced the vulnerable state's sidecar")
	}
	if hv.Sidecars[0] == hp.Sidecars[0] || hv.SidecarNetwork == hp.SidecarNetwork {
		t.Fatalf("states share sidecars: %v %v", hv.Sidecars, hp.Sidecars)
	}
	if got := fe.Resolve(hv.Container, "db"); len(got) != 1 || got[0] != hv.Sidecars[0] {
		t.Fatalf("vulnerable target resolves db to %v", got)
	}
	if got := fe.Resolve(hp.Container, "db"); len(got) != 1 || got[0] != hp.Sidecars[0] {
		t.Fatalf("patched target resolves db to %v", got)
	}
	// A scanner on the shared network sees one container per advertised alias.
	fe.Images["scanner"] = true
	if _, err := fe.ContainerCreate(context.Background(), engine.ContainerSpec{Name: "scanner", Image: "scanner",
		Network: &engine.NetworkAttachment{Name: DefaultNetwork}}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []*Handle{hv, hp} {
		if h.EndpointHost != TargetAlias("sc-demo", h.State) {
			t.Fatalf("endpoint %q", h.EndpointHost)
		}
		if got := fe.Resolve("scanner", h.EndpointHost); len(got) != 1 || got[0] != h.Container {
			t.Fatalf("%s resolves to %v", h.EndpointHost, got)
		}
	}
	if got := fe.Resolve("scanner", "sc-demo"); len(got) != 0 {
		t.Fatalf("the bare id must not resolve on the shared network (ambiguous across states): %v", got)
	}
	if got := fe.Resolve("scanner", "db"); len(got) != 0 {
		t.Fatalf("sidecars are private to their target state: %v", got)
	}
	if err := fe.ContainerRemove(context.Background(), "scanner"); err != nil {
		t.Fatal(err)
	}
	rows, err := r.Running(context.Background(), DefaultNetwork)
	if err != nil || len(rows) != 2 || rows[0].State != "patched" || rows[1].State != "vulnerable" {
		t.Fatalf("ps: %v %+v", err, rows)
	}
	// Re-running one state replaces only that state's containers.
	mustRun(t, r, c, "patched", DefaultExposure())
	if fe.Containers[hv.Sidecars[0]].ID != vulnDB {
		t.Fatal("re-running patched touched the vulnerable sidecar")
	}
	removed, err := r.StopAll(context.Background(), "sc-demo")
	if err != nil || len(removed) != 4 {
		t.Fatalf("stop: %v %v", err, removed)
	}
	if len(fe.Networks) != 1 { // only vulnsuite-net
		t.Fatalf("networks left: %v", fe.Networks)
	}
}

// #42 item 5c: a start interrupted by cancellation still removes what it
// created, on a fresh context.
func TestCancelledStartCleansUp(t *testing.T) {
	fe, r := lifecycleRunner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Labels[LabelRole] == RoleTarget {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if _, err := r.Run(ctx, sidecarContract("slow", "db"), "vulnerable", DefaultExposure(), pullOpts); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if names := containerNames(fe); len(names) != 0 {
		t.Fatalf("cancelled run leaked %v", names)
	}
	if _, ok := fe.Networks[SidecarNetworkName("slow", "vulnerable")]; ok {
		t.Fatal("cancelled run leaked its sidecar network")
	}
}

// Stop and StopAll report removals that failed instead of swallowing them.
func TestStopReportsRemovalErrors(t *testing.T) {
	fe, r := lifecycleRunner()
	h := mustRun(t, r, sidecarContract("stuck", "db"), "vulnerable", DefaultExposure())
	fe.RemoveFn = func(name string) error {
		if name == h.Sidecars[0] {
			return errors.New("device or resource busy")
		}
		return nil
	}
	if err := r.Stop(context.Background(), h); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("Stop swallowed the removal error: %v", err)
	}
	if _, err := r.StopAll(context.Background(), ""); err == nil {
		t.Fatal("StopAll swallowed the removal error")
	}
}

// A sidecar network left by an earlier run is replaced, not reused with its old
// settings, even when a sidecar the template has since renamed still holds it:
// an internal network from a -no-egress run cannot publish ports in host mode.
func TestStaleSidecarNetworkIsReplaced(t *testing.T) {
	fe, r := lifecycleRunner()
	scNet := SidecarNetworkName("sc-demo", "vulnerable")
	noEgress := DefaultExposure()
	noEgress.Internal = true
	mustRun(t, r, sidecarContract("sc-demo", "db"), "vulnerable", noEgress)
	if !fe.Networks[scNet].Internal {
		t.Fatal("setup: the -no-egress run's sidecar network should be internal")
	}
	oldDB := SidecarContainerName("sc-demo", "vulnerable", "db")

	// The template renamed its sidecar db -> postgres; the old one is left running.
	h := mustRun(t, r, sidecarContract("sc-demo", "postgres"), "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"})
	if fe.Networks[scNet].Internal {
		t.Fatal("the stale internal sidecar network was reused: host mode cannot publish from it")
	}
	if _, ok := fe.Containers[oldDB]; ok {
		t.Fatalf("the renamed-away sidecar %s leaked", oldDB)
	}
	if h.EndpointPort == 0 {
		t.Fatalf("no host port published: %+v", h.PublishedPorts)
	}
	if got := fe.Resolve(h.Container, "postgres"); len(got) != 1 {
		t.Fatalf("target resolves postgres to %v", got)
	}
}

// A sidecar network that cannot be removed (a container vulnsuite did not start
// is attached) fails the run instead of being reused with its old settings.
func TestStaleSidecarNetworkRemovalErrorIsReported(t *testing.T) {
	fe, r := lifecycleRunner()
	scNet := SidecarNetworkName("sc-demo", "vulnerable")
	if _, err := fe.NetworkEnsure(context.Background(), engine.NetworkSpec{Name: scNet, Internal: true}); err != nil {
		t.Fatal(err)
	}
	fe.Containers["debug-shell"] = &enginetest.Container{ID: "x1", Running: true,
		Spec: engine.ContainerSpec{Name: "debug-shell", Network: &engine.NetworkAttachment{Name: scNet}}}
	_, err := r.Run(context.Background(), sidecarContract("sc-demo", "db"), "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"}, pullOpts)
	if err == nil || !strings.Contains(err.Error(), scNet) {
		t.Fatalf("want an error naming %s, got %v", scNet, err)
	}
	if _, ok := fe.Containers["debug-shell"]; !ok {
		t.Fatal("removed a container vulnsuite does not manage")
	}
}
