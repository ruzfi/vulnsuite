package contract

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func loadGoodSequence(t *testing.T) *Contract {
	t.Helper()
	data, err := os.ReadFile("testdata/good/sequence.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseSequence(t *testing.T) {
	c := loadGoodSequence(t)
	if c.Service.Sanitizer == nil || c.Service.Sanitizer.LogDir != "/var/log/asan" {
		t.Fatalf("sanitizer = %+v", c.Service.Sanitizer)
	}
	p := c.States[StateVulnerable].Verify[0]
	if p.Kind() != "sequence" {
		t.Fatalf("kind = %q", p.Kind())
	}
	s := p.Sequence
	if s.AttemptCount() != 3 || s.MinHitCount() != 1 || s.TimeoutDuration() != time.Minute {
		t.Fatalf("attempts/min_hits/timeout = %d/%d/%v", s.AttemptCount(), s.MinHitCount(), s.TimeoutDuration())
	}
	var kinds []string
	for _, st := range s.Steps {
		kinds = append(kinds, st.Kind())
	}
	if got := strings.Join(kinds, ","); got != "http,exec,freeze,exec,sleep,resume,expect_sanitizer" {
		t.Fatalf("step kinds = %s", got)
	}
	setup := s.Steps[1].Exec
	if setup.Container != "driver" || setup.Run != "/trigger.py setup" || setup.ExpectExit == nil || setup.Timeout != 5 || !setup.Asserts() || setup.InTarget() {
		t.Fatalf("exec step = %+v", setup)
	}
	if s.Steps[4].Sleep.MS != 100 {
		t.Fatalf("sleep = %+v", s.Steps[4].Sleep)
	}
	es := s.Steps[6].ExpectSanitizer
	if !es.Positive() || es.Kind != "heap-use-after-free" || es.Frame != "ngx_resolver_process_a" {
		t.Fatalf("expect_sanitizer = %+v", es)
	}

	ps := c.States[StatePatched].Verify[1].Sequence
	if ps.MinHitCount() != 1 || ps.TimeoutDuration() != 30500*time.Millisecond {
		t.Fatalf("patched defaults: min_hits %d timeout %v", ps.MinHitCount(), ps.TimeoutDuration())
	}
	if !ps.Steps[0].Exec.InTarget() || ps.Steps[0].Exec.Asserts() {
		t.Fatalf("target exec step = %+v", ps.Steps[0].Exec)
	}
	// The merge key keeps the anchored container and run, adding a timeout.
	if fire := ps.Steps[2].Exec; fire.Container != "driver" || fire.Run != "/trigger.py fire" || fire.Timeout != 10 {
		t.Fatalf("merged exec step = %+v", fire)
	}
	if !ps.Steps[4].ExpectSanitizer.None || ps.Steps[4].ExpectSanitizer.Positive() {
		t.Fatalf("expect_sanitizer: none = %+v", ps.Steps[4].ExpectSanitizer)
	}
	if *ps.Steps[5].ExpectLog == "" || !ps.Steps[6].IsNetwork() || !ps.Steps[7].IsNetwork() || ps.Steps[5].IsNetwork() {
		t.Fatal("expect_log / network steps")
	}
}

func TestSequenceDefaults(t *testing.T) {
	var s SequenceProbe
	if s.AttemptCount() != 1 || s.MinHitCount() != 1 || s.TimeoutDuration() != 60*time.Second {
		t.Fatalf("defaults = %d/%d/%v", s.AttemptCount(), s.MinHitCount(), s.TimeoutDuration())
	}
	if (Probe{}).Kind() != "" || (SequenceStep{}).Kind() != "" {
		t.Fatal("empty kinds")
	}
}

// -json output (info, run) carries the sequence, with expect_sanitizer in its
// contract spelling, and a contract without one is unchanged.
func TestSequenceJSON(t *testing.T) {
	c := loadGoodSequence(t)
	b, err := json.Marshal(c.States[StatePatched].Verify[1])
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"sequence":{"attempts":3,`, `"expect_sanitizer":"none"`, `"exec":{"run":"test -d /var/log/asan"}`, `"freeze":{}`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON %s lacks %s", got, want)
		}
	}
	b, _ = json.Marshal(c.States[StateVulnerable].Verify[0].Sequence.Steps[6])
	if string(b) != `{"expect_sanitizer":{"kind":"heap-use-after-free","frame":"ngx_resolver_process_a"}}` {
		t.Errorf("positive expect_sanitizer JSON = %s", b)
	}
	b, _ = json.Marshal(c.Service)
	if !strings.Contains(string(b), `"sanitizer":{"log_dir":"/var/log/asan"}`) {
		t.Errorf("service JSON = %s", b)
	}
	b, _ = json.Marshal(Service{})
	if strings.Contains(string(b), "sanitizer") {
		t.Errorf("an unset sanitizer must not appear in JSON: %s", b)
	}
	b, _ = json.Marshal(Probe{Exec: &ExecProbe{Run: "x"}})
	if string(b) != `{"exec":{"run":"x"}}` {
		t.Errorf("exec probe JSON changed: %s", b)
	}
}

func TestExpectSanitizerYAMLRoundTrip(t *testing.T) {
	for _, in := range []ExpectSanitizer{{None: true}, {Kind: "heap-buffer-overflow", Frame: "f.*"}} {
		b, err := yaml.Marshal(SequenceStep{ExpectSanitizer: &in})
		if err != nil {
			t.Fatal(err)
		}
		var out SequenceStep
		if err := yaml.UnmarshalWithOptions(b, &out, yaml.Strict()); err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		if *out.ExpectSanitizer != in {
			t.Errorf("round trip of %+v via %s = %+v", in, b, *out.ExpectSanitizer)
		}
	}
}

// service.sanitizer is read at run time; it must not change any image tag, so
// adding it to an existing template rebuilds nothing.
func TestContentHashIgnoresSanitizer(t *testing.T) {
	overlay := "    overlay: [ { src: files/a.conf, dest: /etc/a.conf } ]\n"
	without := hashDoc(t, hashHead+overlay).ContentHash("vulnerable")
	with := hashDoc(t, strings.Replace(hashHead,
		"service: { ports: [ { container: 80, protocol: http } ] }",
		"service: { ports: [ { container: 80, protocol: http } ], sanitizer: { log_dir: /var/log/asan } }", 1)+overlay).ContentHash("vulnerable")
	if without != with {
		t.Fatalf("sanitizer changed the hash: %s != %s", without, with)
	}
	seq := hashDoc(t, hashHead+overlay+"    verify: [ { sequence: { steps: [ { freeze: {} }, { resume: {} }, { expect_log: x } ] } } ]\n").ContentHash("vulnerable")
	if seq != without {
		t.Fatalf("a verify probe changed the hash: %s != %s", seq, without)
	}
}
