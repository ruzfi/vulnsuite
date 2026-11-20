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
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// sequenceProbe drives a sidecar and asserts a sanitizer report.
func sequenceProbe() contract.Probe {
	return contract.Probe{Sequence: &contract.SequenceProbe{Steps: []contract.SequenceStep{
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "/trigger.py setup"}, Container: "driver"}},
		{Freeze: &contract.FreezeStep{}},
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "/trigger.py fire"}, Container: "driver"}},
		{Resume: &contract.ResumeStep{}},
		{ExpectSanitizer: &contract.ExpectSanitizer{Kind: "heap-use-after-free"}},
	}}}
}

// Until the sequence executor lands (#98), a sequence fails verify with a
// clear detail when the target is unreachable from here: it is neither run as
// an exec probe nor skipped as a network probe, so it can never leave a
// target "verified" or quietly unverified.
func TestUnreachableTargetFailsSequenceProbes(t *testing.T) {
	shadow := contract.Probe{Exec: &contract.ExecProbe{Run: "cat /etc/shadow", StdoutMatches: "root:"}}
	tcp := contract.Probe{TCP: &contract.TCPProbe{Port: 6379}}
	for name, tc := range map[string]struct {
		verify  []contract.Probe
		details []string
		absent  []string
	}{
		"sequence only":           {[]contract.Probe{sequenceProbe()}, []string{"FAIL " + probes.SequenceUnsupported}, []string{"skip"}},
		"sequence and exec":       {[]contract.Probe{shadow, sequenceProbe()}, []string{"ok   exec", "FAIL " + probes.SequenceUnsupported}, []string{"skip"}},
		"sequence and network":    {[]contract.Probe{sequenceProbe(), tcp}, []string{"FAIL " + probes.SequenceUnsupported, "skip 1 network probe(s)"}, nil},
		"sequence, exec, network": {[]contract.Probe{tcp, shadow, sequenceProbe()}, []string{"ok   exec", "FAIL sequence", "skip 1 network probe(s)"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			fe := enginetest.New()
			fe.ExecFn = func(_, cmd string) (int, string, error) {
				if strings.Contains(cmd, "trigger.py") {
					t.Errorf("a sequence step ran: %q", cmd)
				}
				if cmd == "cat /etc/shadow" {
					return 0, "root:x:0:0", nil
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
			if h.VerifyOK == nil || *h.VerifyOK {
				t.Fatalf("VerifyOK = %v, want false; detail %q", deref(h.VerifyOK), h.VerifyDetail)
			}
			for _, d := range tc.details {
				if !strings.Contains(h.VerifyDetail, d) {
					t.Errorf("detail %q lacks %q", h.VerifyDetail, d)
				}
			}
			for _, d := range tc.absent {
				if strings.Contains(h.VerifyDetail, d) {
					t.Errorf("detail %q has %q", h.VerifyDetail, d)
				}
			}
			var kinds []string
			for _, p := range h.Probes {
				kinds = append(kinds, p.Kind)
			}
			if !strings.Contains(strings.Join(kinds, ","), "sequence") {
				t.Errorf("probe results %v lack the sequence", kinds)
			}
		})
	}
}

// On a reachable target a sequence fails verify too, even when every other
// probe passes.
func TestReachableTargetFailsSequenceProbes(t *testing.T) {
	fe := enginetest.New()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		for _, p := range spec.Ports {
			l, err := net.Listen("tcp", net.JoinHostPort(p.HostIP, strconv.Itoa(p.HostPort)))
			if err != nil {
				return err
			}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
			srv.Listener.Close()
			srv.Listener = l
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.Start()
			t.Cleanup(srv.Close)
		}
		return nil
	}
	fe.ExecFn = func(_, cmd string) (int, string, error) {
		t.Errorf("nothing should exec in the target: %q", cmd)
		return 0, "", nil
	}
	status := 200
	c := &contract.Contract{
		APIVersion: contract.APIVersion,
		Kind:       "Target",
		Metadata:   contract.Metadata{ID: "sequence-stub-test"},
		Base:       contract.Base{Kind: contract.BaseImage, Image: "example:latest"},
		Service:    contract.Service{Ports: []contract.Port{{Container: 8080, Protocol: "http"}}},
		States: map[string]*contract.State{"vulnerable": {Name: "vulnerable", Verify: []contract.Probe{
			{HTTP: &contract.HTTPProbe{Status: &status, BodyMatches: "ok"}},
			sequenceProbe(),
		}}},
	}
	h, err := New(fe).Run(context.Background(), c, "vulnerable", Exposure{Mode: ModeHost, Bind: "127.0.0.1"},
		Options{Verify: true, ReadyTimeout: 3 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.VerifyOK == nil || *h.VerifyOK {
		t.Fatalf("VerifyOK = %v, want false; detail %q", deref(h.VerifyOK), h.VerifyDetail)
	}
	if !strings.Contains(h.VerifyDetail, "ok   / -> 200") || !strings.Contains(h.VerifyDetail, "FAIL "+probes.SequenceUnsupported) {
		t.Fatalf("detail %q", h.VerifyDetail)
	}
}
