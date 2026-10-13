package runner

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

func load(t *testing.T, id string) *contract.Contract {
	t.Helper()
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "templates"))
	c, err := loader.New(root).LoadSelector(id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRunInternalBuildsSpecAndFleet(t *testing.T) {
	fe := enginetest.New()
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	c := load(t, "apache-httpd-2.4.49-cve-2021-41773")
	ctx := context.Background()
	// The fake's container IPs are not routable, so readiness falls back to
	// "running" and verification is skipped with an explanation.
	h, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), Options{Verify: true, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Container != "vulnsuite-apache-httpd-2.4.49-cve-2021-41773-vulnerable" || h.EndpointHost != c.ID() || h.EndpointPort != 80 || h.Scheme != "http" {
		t.Fatalf("handle: %+v", h)
	}
	if h.ScannerTarget() != "http://apache-httpd-2.4.49-cve-2021-41773:80" {
		t.Fatal(h.ScannerTarget())
	}
	if !h.Ready || h.VerifyOK != nil || h.VerifyDetail == "" {
		t.Fatalf("ready=%v verify=%v detail=%q", h.Ready, h.VerifyOK, h.VerifyDetail)
	}
	spec := fe.Containers[h.Container].Spec
	if spec.Network == nil || spec.Network.Name != DefaultNetwork || spec.Network.Aliases[0] != c.ID() {
		t.Fatalf("network: %+v", spec.Network)
	}
	if len(spec.SecurityOpt) != 1 || spec.SecurityOpt[0] != "no-new-privileges:true" {
		t.Fatalf("hardening: %v", spec.SecurityOpt)
	}
	if spec.Labels[LabelManaged] != "true" || spec.Labels[builder.LabelID] != c.ID() {
		t.Fatalf("labels: %v", spec.Labels)
	}
	if _, ok := fe.Networks[DefaultNetwork]; !ok {
		t.Fatal("internal network must be created")
	}
	rows, err := r.Running(ctx, DefaultNetwork)
	if err != nil || len(rows) != 1 || rows[0].ID != c.ID() || rows[0].State != "vulnerable" || rows[0].IP == "" {
		t.Fatalf("running: %v %+v", err, rows)
	}
	// re-running the same state replaces the container instead of conflicting
	if _, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), Options{}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	removed, err := r.StopAll(ctx, "")
	if err != nil || len(removed) != 1 {
		t.Fatalf("stop: %v %v", err, removed)
	}
	if rows, _ := r.Running(ctx, DefaultNetwork); len(rows) != 0 {
		t.Fatal("still running after stop")
	}
}

func TestRunHostModeAndEnvCommandDevices(t *testing.T) {
	fe := enginetest.New()
	r := New(fe)
	r.Reach = func(string, int, time.Duration) probes.Reach { return probes.Unreachable }
	c := load(t, "redis-unauthenticated-access")
	ctx := context.Background()
	exp := Exposure{Mode: ModeHost, Bind: "127.0.0.1", HostPort: 0}
	h, err := r.Run(ctx, c, "patched", exp, Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	spec := fe.Containers[h.Container].Spec
	if len(spec.Ports) != 1 || spec.Ports[0].ContainerPort != 6379 || spec.Ports[0].HostPort == 0 || h.EndpointPort != spec.Ports[0].HostPort {
		t.Fatalf("ports: %+v %d", spec.Ports, h.EndpointPort)
	}
	if h.Scheme != "" || h.ScannerTarget() != FormatTarget("", "127.0.0.1", h.EndpointPort) {
		t.Fatalf("raw tcp target: %q", h.ScannerTarget())
	}
	if len(spec.Cmd) != 2 || spec.Cmd[0] != "redis-server" {
		t.Fatalf("command: %v", spec.Cmd)
	}
	// macvlan needs a parent
	if _, err := r.Run(ctx, c, "patched", Exposure{Mode: ModeMacvlan}, Options{}); err == nil {
		t.Fatal("macvlan without -parent must fail")
	}
	// unknown mode
	if _, err := r.Run(ctx, c, "patched", Exposure{Mode: "bogus"}, Options{}); err == nil {
		t.Fatal("unknown mode must fail")
	}
}

func TestSidecarCommandReachesEngine(t *testing.T) {
	fe := enginetest.New()
	r := New(fe)
	c := &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       "Target",
		Metadata:   contract.Metadata{ID: "sidecar-cmd-test"},
		Service: contract.Service{
			Sidecars: []contract.Sidecar{{
				Name:    "node2",
				Image:   "minio/minio:vuln",
				Command: []string{"server", "http://node1/data", "http://node2/data"},
			}},
		},
	}
	// patched state swaps the sidecar image to the fixed version.
	st := &contract.State{
		Name:     "patched",
		Sidecars: map[string]contract.SidecarOverride{"node2": {Image: "minio/minio:fixed"}},
	}
	exp := Exposure{Mode: ModeInternal, Network: DefaultNetwork}
	names, err := r.startSidecars(context.Background(), c, st, exp)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 sidecar, got %v", names)
	}
	sc := fe.Containers[names[0]]
	if sc == nil {
		t.Fatalf("sidecar %q not recorded", names[0])
	}
	cmd := sc.Spec.Cmd
	if len(cmd) != 3 || cmd[0] != "server" || cmd[2] != "http://node2/data" {
		t.Fatalf("sidecar command not threaded: %v", cmd)
	}
	// the per-state override wins over the sidecar's own image
	if sc.Spec.Image != "minio/minio:fixed" {
		t.Fatalf("sidecar override not applied: %s", sc.Spec.Image)
	}
	// and it joins the network under its bare name, so peers can resolve it
	if sc.Spec.Network == nil || len(sc.Spec.Network.Aliases) != 1 || sc.Spec.Network.Aliases[0] != "node2" {
		t.Fatalf("sidecar alias: %+v", sc.Spec.Network)
	}
}

func TestMergeEnvAndNames(t *testing.T) {
	env := mergeEnv(map[string]string{"A": "1", "B": "2"}, map[string]string{"B": "3"})
	if len(env) != 2 || env[0] != "A=1" || env[1] != "B=3" {
		t.Fatal(env)
	}
	if FormatTarget("https", "::1", 443) != "https://[::1]:443" {
		t.Fatal(FormatTarget("https", "::1", 443))
	}
}
