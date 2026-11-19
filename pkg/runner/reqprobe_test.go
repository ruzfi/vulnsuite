package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// reqProbeFake answers a requires.probe container (a hostprobe-labelled one)
// with code and out; other containers start normally. probes collects the
// probe specs.
func reqProbeFake(code int, out string, probeSpecs *[]engine.ContainerSpec) *enginetest.Fake {
	fe := enginetest.New()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		if spec.Labels[LabelHostProbe] != "" {
			*probeSpecs = append(*probeSpecs, spec)
			if code >= 0 {
				fe.Exit(spec.Name, code)
			} // code < 0: never exits
		}
		return nil
	}
	fe.LogsFn = func(spec engine.ContainerSpec) string {
		if spec.Labels[LabelHostProbe] != "" {
			return out
		}
		return ""
	}
	return fe
}

func withProbe(t *testing.T, p contract.RequiresProbe) *contract.Contract {
	c := load(t, "apache-httpd-2.4.49-cve-2021-41773")
	c.Requires.Probe = &p
	return c
}

// #119 item 2: a failing requires.probe skips the target before anything of
// it starts; a passing one lets it run.
func TestRunRequiresProbe(t *testing.T) {
	ctx := context.Background()
	opts := Options{Build: builder.Options{Pull: true}}
	unreachable := func(string, int, time.Duration) probes.Reach { return probes.Unreachable }

	var specs []engine.ContainerSpec
	fe := reqProbeFake(1, "no vbmi here\n", &specs)
	r := New(fe)
	r.Reach = unreachable
	c := withProbe(t, contract.RequiresProbe{Run: "grep -qw avx512vbmi /proc/cpuinfo", Reason: "needs AVX-512 VBMI"})
	_, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), opts)
	se, ok := AsSkip(err)
	if !ok {
		t.Fatalf("want a skip, got %v", err)
	}
	d := se.Decision
	if d.Cause != CauseProbe || !strings.HasPrefix(d.Reason, "needs AVX-512 VBMI (") || !strings.Contains(d.Reason, "exited 1: no vbmi here") {
		t.Fatalf("decision %+v", d)
	}
	if len(fe.Containers) != 0 || len(fe.Networks) != 0 {
		t.Fatalf("something started before the probe decided: %v %v", fe.Containers, fe.Networks)
	}
	if len(specs) != 1 {
		t.Fatalf("%d probe containers", len(specs))
	}
	s := specs[0]
	img := "vulnsuite/apache-httpd-2.4.49-cve-2021-41773:vulnerable-" // the resolved state image
	if !strings.Contains(s.Image, img) || !reflect.DeepEqual(s.Entrypoint, []string{"/bin/sh", "-c"}) ||
		!reflect.DeepEqual(s.Cmd, []string{"grep -qw avx512vbmi /proc/cpuinfo"}) || s.Network == nil || s.Network.Name != "none" ||
		!reflect.DeepEqual(s.CapDrop, []string{"ALL"}) || len(s.Devices) != 0 || len(s.Ports) != 0 {
		t.Fatalf("probe spec %+v", s)
	}

	// Exit 0: the target runs.
	specs = nil
	fe = reqProbeFake(0, "", &specs)
	r = New(fe)
	r.Reach = unreachable
	if h, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), opts); err != nil || h == nil || len(specs) != 1 {
		t.Fatalf("passing probe: %v, %d probe(s)", err, len(specs))
	}

	// -ignore-requires: the probe is not run.
	specs = nil
	fe = reqProbeFake(1, "", &specs)
	r = New(fe)
	r.Reach = unreachable
	ign := opts
	ign.IgnoreRequires = true
	if _, err := r.Run(ctx, c, "vulnerable", DefaultExposure(), ign); err != nil || len(specs) != 0 {
		t.Fatalf("-ignore-requires: %v, %d probe(s)", err, len(specs))
	}
}

// A probe that cannot run is an error (a broken template or daemon), not a skip.
func TestRequiresProbeErrors(t *testing.T) {
	ctx := context.Background()
	var specs []engine.ContainerSpec
	fe := reqProbeFake(-1, "", &specs) // never exits
	fe.Images["img:1"] = true
	c := withProbe(t, contract.RequiresProbe{Run: "sleep 999", Reason: "x", Timeout: "1s"})
	start := time.Now()
	_, err := RequiresProbe(ctx, fe, c, "vulnerable", "img:1", "")
	if err == nil || !strings.Contains(err.Error(), "did not exit within 1s") || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout: %v after %s", err, time.Since(start))
	}
	if len(fe.Containers) != 0 {
		t.Fatal("timed-out probe container left behind")
	}

	fe = reqProbeFake(0, "", &specs)
	fe.Images["img:1"] = true
	fe.StartFn = func(engine.ContainerSpec) error {
		return errString(`exec: "/bin/sh": stat /bin/sh: no such file or directory`)
	}
	if _, err := RequiresProbe(ctx, fe, c, "vulnerable", "img:1", ""); err == nil || !strings.Contains(err.Error(), "/bin/sh") {
		t.Fatalf("no shell: %v", err)
	}

	// The probe runs for the target's platform (emulation).
	specs = nil
	fe = reqProbeFake(0, "", &specs)
	fe.Images["img:1"] = true
	if d, err := RequiresProbe(ctx, fe, c, "vulnerable", "img:1", "linux/amd64"); err != nil || d.Skip() || specs[0].Platform != "linux/amd64" {
		t.Fatalf("platform: %v %+v %+v", err, d, specs)
	}
	// No probe: native, nothing run.
	specs = nil
	if d, err := RequiresProbe(ctx, fe, load(t, "apache-httpd-2.4.49-cve-2021-41773"), "vulnerable", "img:1", ""); err != nil || d.Action != ActionNative || len(specs) != 0 {
		t.Fatalf("no probe: %v %+v", err, d)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
