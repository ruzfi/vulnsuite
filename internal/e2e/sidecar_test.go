package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/loader"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// sidecarContract runs the e2e server as the target and again as its "db"
// sidecar, each state on its own build, so /peer (the target asking db for
// /whoami) proves which sidecar the target's "db" resolves to.
const sidecarContract = `apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: e2e-sidecar-dns
  summary: e2e fixture, a target that must resolve its sidecar by name
  vuln_refs: [VS-E2E-SIDECAR]
  severity: low
  references: [https://example.invalid]
  detection: custom-only
base:
  kind: image
  image: VULN_IMAGE
service:
  ports: [ { container: 8080, protocol: http } ]
  healthcheck: { http: { path: /whoami, status: 200 }, timeout: 30s }
  sidecars:
    - { name: db, image: VULN_IMAGE }
states:
  vulnerable:
    verify:
      - http: { path: /peer, status: 200, body_matches: "mode=vulnerable" }
  patched:
    image: PATCHED_IMAGE
    sidecars: { db: { image: PATCHED_IMAGE } }
    verify:
      - http: { path: /peer, status: 200, body_matches: "mode=patched" }
`

func httpGet(u string) (string, error) {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(b), fmt.Errorf("%s: %s", u, resp.Status)
	}
	return string(b), err
}

func sidecarPhase(ctx context.Context, t *testing.T, eng engine.Engine, r *runner.Runner, store *loader.Store, root string, base *contract.Contract) {
	t.Helper()
	dir := filepath.Join(root, "fixtures", "e2e-sidecar-dns")
	must(t, os.MkdirAll(dir, 0o755))
	y := strings.ReplaceAll(sidecarContract, "VULN_IMAGE", base.ImageTag("vulnerable"))
	y = strings.ReplaceAll(y, "PATCHED_IMAGE", base.ImageTag("patched"))
	must(t, os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(y), 0o644))
	c, err := store.LoadSelector("e2e-sidecar-dns")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := r.StopAll(context.Background(), c.ID()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	states := []string{"vulnerable", "patched"}

	// Host mode, both states at once: each target publishes its port and
	// resolves "db" to its own state's sidecar (verify asks /peer).
	hosts := map[string]*runner.Handle{}
	for _, state := range states {
		h, err := r.Run(ctx, c, state, runner.Exposure{Mode: runner.ModeHost, Bind: "127.0.0.1"}, runner.Options{Verify: true})
		if err != nil {
			t.Fatalf("sidecar host %s: %v", state, err)
		}
		if !h.Ready || h.VerifyOK == nil || !*h.VerifyOK {
			t.Fatalf("sidecar host %s: ready=%v verify: %s", state, h.Ready, h.VerifyDetail)
		}
		hosts[state] = h
	}
	vulnDB, err := eng.ContainerInspect(ctx, hosts["vulnerable"].Sidecars[0])
	if err != nil {
		t.Fatalf("vulnerable sidecar gone after starting patched: %v", err)
	}
	for _, state := range states { // repeat: a shared alias would answer at random
		for i := 0; i < 4; i++ {
			body, err := httpGet(hosts[state].ScannerTarget() + "/peer")
			if err != nil || !strings.Contains(body, "mode="+state) {
				t.Fatalf("host %s /peer #%d: %q %v", state, i, body, err)
			}
		}
	}
	rows, err := r.Running(ctx, runner.DefaultNetwork)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, row := range rows {
		if row.ID == c.ID() {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("ps should list two %s targets (no sidecars): %+v", c.ID(), rows)
	}
	for _, state := range states {
		if err := r.Stop(ctx, hosts[state]); err != nil {
			t.Fatalf("stop host %s: %v", state, err)
		}
		if ok, _ := eng.NetworkExists(ctx, hosts[state].SidecarNetwork); ok {
			t.Fatalf("stop left network %s", hosts[state].SidecarNetwork)
		}
	}
	t.Logf("host mode: both states resolve their own db (vulnerable db %s)", vulnDB.ID[:12])

	// Internal mode, both states at once: the per-state alias reaches exactly
	// that state, from another container on the shared network.
	internal := map[string]*runner.Handle{}
	for _, state := range states {
		h, err := r.Run(ctx, c, state, runner.DefaultExposure(), runner.Options{Verify: true})
		if err != nil {
			t.Fatalf("sidecar internal %s: %v", state, err)
		}
		if h.EndpointHost != runner.TargetAlias(c.ID(), state) {
			t.Fatalf("endpoint %q", h.EndpointHost)
		}
		internal[state] = h
	}
	// A probe container of our own on the shared network, published on the
	// host, asks for each alias (container IPs may not be routable from here).
	probe := fmt.Sprintf("e2e-alias-probe-%d", os.Getpid())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probePort := l.Addr().(*net.TCPAddr).Port
	l.Close()
	t.Cleanup(func() { _ = eng.ContainerRemove(context.Background(), probe) })
	pid, err := eng.ContainerCreate(ctx, engine.ContainerSpec{Name: probe, Image: base.ImageTag("vulnerable"),
		Network: &engine.NetworkAttachment{Name: runner.DefaultNetwork},
		Ports:   []engine.PortBinding{{HostIP: "127.0.0.1", HostPort: probePort, ContainerPort: 8080, Protocol: "tcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	must(t, eng.ContainerStart(ctx, pid))
	fetch := func(target string) (string, error) {
		u := fmt.Sprintf("http://127.0.0.1:%d/fetch?u=%s", probePort, url.QueryEscape(target))
		var body string
		var err error
		for i := 0; i < 20; i++ { // the probe may still be starting
			if body, err = httpGet(u); err == nil {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		return strings.TrimSpace(body), err
	}
	for _, state := range states {
		alias := runner.TargetAlias(c.ID(), state)
		for i := 0; i < 6; i++ { // a shared alias would answer with a random state
			if body, err := fetch("http://" + alias + ":8080/whoami"); err != nil || body != "mode="+state {
				t.Fatalf("alias %s #%d answered %q (%v)", alias, i, body, err)
			}
			if body, err := fetch("http://" + alias + ":8080/peer"); err != nil || body != "mode="+state {
				t.Fatalf("%s resolved db to %q (%v)", alias, body, err)
			}
		}
	}
	if body, err := fetch("http://db:8080/whoami"); err == nil {
		t.Fatalf("sidecars must be private to their target state, but db answered on %s: %q", runner.DefaultNetwork, body)
	}
	must(t, eng.ContainerRemove(ctx, probe))
	t.Logf("internal mode: aliases %s and %s each resolve to one state, with its own db",
		runner.TargetAlias(c.ID(), "vulnerable"), runner.TargetAlias(c.ID(), "patched"))
	removed, err := r.StopAll(ctx, c.ID())
	if err != nil || len(removed) != 4 {
		t.Fatalf("stop: %v %v", err, removed)
	}
	for _, state := range states {
		if ok, _ := eng.NetworkExists(ctx, runner.SidecarNetworkName(c.ID(), state)); ok {
			t.Fatalf("stop -t left the %s sidecar network", state)
		}
	}
}
