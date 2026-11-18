package runner

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// A target with an https primary port and a plain-HTTP secondary port: each
// probe must speak the scheme of the port it names.
func TestVerifyProbesUseEachPortsScheme(t *testing.T) {
	fe := enginetest.New()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		for _, p := range spec.Ports {
			l, err := net.Listen("tcp", net.JoinHostPort(p.HostIP, strconv.Itoa(p.HostPort)))
			if err != nil {
				return err
			}
			body := fmt.Sprintf("port-%d", p.ContainerPort)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			srv.Listener.Close()
			srv.Listener = l
			srv.Config.ErrorLog = log.New(io.Discard, "", 0) // readiness dials without a handshake
			if p.ContainerPort == 8443 {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			t.Cleanup(srv.Close)
		}
		return nil
	}
	r := New(fe)
	status := 200
	c := &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       "Target",
		Metadata:   contract.Metadata{ID: "mixed-scheme-test"},
		Base:       contract.Base{Kind: contract.BaseImage, Image: "example:latest"},
		Service: contract.Service{Ports: []contract.Port{
			{Container: 8443, Protocol: "https"},
			{Container: 8080, Protocol: "http", Publish: true},
		}},
		States: map[string]*contract.State{"vulnerable": {Name: "vulnerable", Verify: []contract.Probe{
			{HTTP: &contract.HTTPProbe{Status: &status, BodyMatches: "port-8443"}},
			{HTTP: &contract.HTTPProbe{Port: 8443, BodyMatches: "port-8443"}},
			{HTTP: &contract.HTTPProbe{Port: 8080, BodyMatches: "port-8080"}},
		}}},
	}
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{Verify: true, ReadyTimeout: 3 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.VerifyOK == nil || !*h.VerifyOK {
		t.Fatalf("verify should pass with each probe on its port's scheme: %v\n%s", h.VerifyOK, h.VerifyDetail)
	}
}

// A wildcard bind is dialled via loopback whichever address family it names:
// -bind :: must behave like -bind 0.0.0.0.
func TestHostModeWildcardBindEndpoint(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::"} {
		fe := enginetest.New()
		r := New(fe)
		c := load(t, "redis-unauthenticated-access")
		h, err := r.Run(context.Background(), c, "patched", Exposure{Mode: ModeHost, Bind: bind},
			Options{ReadyTimeout: time.Second, Build: builder.Options{Pull: true}})
		if err != nil {
			t.Fatalf("bind %s: %v", bind, err)
		}
		if h.EndpointHost != "127.0.0.1" {
			t.Errorf("bind %s: endpoint host %q, want 127.0.0.1", bind, h.EndpointHost)
		}
		if got, want := h.ScannerTarget(), FormatTarget("", "127.0.0.1", h.EndpointPort); got != want {
			t.Errorf("bind %s: scanner target %q, want %q", bind, got, want)
		}
		if spec := fe.Containers[h.Container].Spec; len(spec.Ports) != 1 || spec.Ports[0].HostIP != bind {
			t.Errorf("bind %s: the daemon must still be asked to bind %s: %+v", bind, bind, spec.Ports)
		}
	}
}

// -bind :: on a remote daemon publishes on the daemon host, which this machine
// reaches only as its own loopback: report it as unverifiable from here, not a
// wrong state, without burning the healthcheck timeout.
func TestVerifyRemoteDaemonIPv6WildcardBind(t *testing.T) {
	fe := enginetest.New()
	fe.HostAddr = "tcp://10.0.0.5:2375"
	r := New(fe)
	c := load(t, "grafana-8.3.0-cve-2021-43798")
	start := time.Now()
	h, err := r.Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "::"},
		Options{Verify: true, ReadyTimeout: 10 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.VerifyOK != nil {
		t.Fatalf("verify should be reported as unverifiable, not pass/fail: %v %s", *h.VerifyOK, h.VerifyDetail)
	}
	if !strings.Contains(h.VerifyDetail, "-bind") || !strings.Contains(h.VerifyDetail, "remote") {
		t.Fatalf("detail should name the fix: %q", h.VerifyDetail)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("burned the healthcheck timeout against a remote daemon's loopback: %s", elapsed)
	}
	if !h.Ready {
		t.Fatal("the engine reports the container running; it should be ready")
	}
}
