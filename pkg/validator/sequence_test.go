package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seqDoc builds a contract whose vulnerable state verifies with one sequence
// made of steps (YAML flow mappings). service holds extra service keys.
func seqDoc(service string, steps ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: seq-rules, summary: x }
base: { kind: image, image: nginx:1.27, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service:
  ports: [ { container: 80, protocol: http } ]
  sidecars: [ { name: driver, image: "python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } ]
%sstates:
  vulnerable:
    verify:
      - sequence:
          steps:
`, service)
	for _, s := range steps {
		fmt.Fprintf(&b, "            - %s\n", s)
	}
	return b.String()
}

const logDir = "  sanitizer: { log_dir: /var/log/asan }\n"

// The proposal's own vulnerable and patched sequences are clean.
var (
	goodVulnerable = []string{`exec: { container: driver, run: "/t setup" }`, `freeze: {}`,
		`exec: { container: driver, run: "/t fire" }`, `resume: {}`,
		`expect_sanitizer: { kind: heap-use-after-free, frame: "ngx_resolver_process_a" }`}
	goodPatched = []string{`exec: { container: driver, run: "/t setup" }`, `freeze: {}`,
		`exec: { container: driver, run: "/t fire" }`, `resume: {}`,
		`expect_sanitizer: none`, `expect_log: "writev\\(\\) failed"`}
)

var sequenceRules = []string{"sequence-unbalanced-freeze", "exec-in-frozen-target", "network-step-while-frozen",
	"unknown-sidecar", "sanitizer-without-log-dir", "sequence-no-assertion", "race-no-positive-control",
	"sanitizer-log-path", "bad-regex", "undeclared-port", "sanitizer-while-frozen"}

func TestSequenceRules(t *testing.T) {
	with := func(steps []string, i int, s string) []string {
		out := append([]string{}, steps...)
		return append(out[:i], append([]string{s}, out[i:]...)...)
	}
	cases := []struct {
		name    string
		service string
		steps   []string
		want    string // the one sequence rule expected, "" for none
		level   Level
	}{
		{"good vulnerable", logDir, goodVulnerable, "", ""},
		{"good patched", logDir, goodPatched, "", ""},
		{"freeze without resume", logDir, append(goodVulnerable[:3:3], "expect_log: x"), "sequence-unbalanced-freeze", Error},
		{"nested freeze", logDir, with(goodVulnerable, 2, "freeze: {}"), "sequence-unbalanced-freeze", Error},
		{"resume without freeze", logDir, []string{"resume: {}", "expect_log: x"}, "sequence-unbalanced-freeze", Error},
		{"second window is fine", logDir, append(append([]string{}, goodVulnerable[:4]...), goodVulnerable[1:]...), "", ""},
		{"exec in frozen target", logDir, with(goodVulnerable, 2, `exec: { run: "kill -0 1" }`), "exec-in-frozen-target", Error},
		{"exec in target outside freeze", logDir, with(goodVulnerable, 0, `exec: { run: "true" }`), "", ""},
		{"exec in target with empty container", logDir, with(goodVulnerable, 2, `exec: { container: "", run: "true" }`), "exec-in-frozen-target", Error},
		{"http while frozen", logDir, with(goodVulnerable, 2, `http: { path: / }`), "network-step-while-frozen", Error},
		{"tcp while frozen", logDir, with(goodVulnerable, 2, `tcp: { port: 80 }`), "network-step-while-frozen", Error},
		{"net while frozen", logDir, with(goodVulnerable, 2, `net: { steps: [ { expect: x } ] }`), "network-step-while-frozen", Error},
		{"http outside freeze", logDir, with(goodVulnerable, 0, `http: { path: /, status: 200 }`), "", ""},
		{"sleep and expect while frozen", logDir, with(with(goodVulnerable, 2, "sleep: { ms: 50 }"), 3, "expect_log: x"), "", ""},
		{"none while frozen", logDir, with(goodPatched, 2, "expect_sanitizer: none"), "sanitizer-while-frozen", Warning},
		{"positive while frozen", logDir, with(goodVulnerable, 2, "expect_sanitizer: { kind: heap-use-after-free }"), "sanitizer-while-frozen", Warning},
		{"unknown sidecar", logDir, with(goodVulnerable, 0, `exec: { container: dns, run: "true" }`), "unknown-sidecar", Error},
		{"sanitizer without log_dir", "", goodVulnerable, "sanitizer-without-log-dir", Error},
		{"none without log_dir", "", goodPatched, "sanitizer-without-log-dir", Error},
		{"expect_log needs no log_dir", "", []string{`exec: { container: driver, run: x }`, "expect_log: x"}, "", ""},
		{"no assertion", logDir, []string{`exec: { container: driver, run: x }`, "freeze: {}", "resume: {}", "sleep: { ms: 1 }", "http: { path: /, status: 200 }"}, "sequence-no-assertion", Error},
		{"asserting exec", logDir, []string{`exec: { container: driver, run: x, expect_exit: 1 }`}, "", ""},
		{"exec stdout assertion", logDir, []string{`exec: { container: driver, run: x, stdout_matches: crash }`}, "", ""},
		{"none without positive control", logDir, goodPatched[:5], "race-no-positive-control", Warning},
		{"bad frame", logDir, append(goodVulnerable[:4:4], `expect_sanitizer: { kind: heap-use-after-free, frame: "(" }`), "bad-regex", Error},
		{"bad expect_log", logDir, []string{`expect_log: "a["`}, "bad-regex", Error},
		{"bad stdout_matches", logDir, []string{`exec: { container: driver, run: x, stdout_matches: "*" }`}, "bad-regex", Error},
		{"bad net step", logDir, []string{`net: { steps: [ { expect: "(" } ] }`, "expect_log: x"}, "bad-regex", Error},
		{"undeclared step port", logDir, []string{`tcp: { port: 8081 }`, "expect_log: x"}, "undeclared-port", Warning},
		{"closed step port", logDir, []string{`tcp: { port: 8081, closed: true }`, "expect_log: x"}, "", ""},
		{"log_path in log_dir", logDir + "  environment: { ASAN_OPTIONS: \"halt_on_error=1:log_path=/var/log/asan/asan\" }\n", goodVulnerable, "", ""},
		{"log_path outside log_dir", logDir + "  environment: { ASAN_OPTIONS: \"log_path=/var/log/nginx/asan:halt_on_error=1\" }\n", goodVulnerable, "sanitizer-log-path", Warning},
		{"log_path in a subdirectory", logDir + "  environment: { ASAN_OPTIONS: \"log_path=/var/log/asan/x/asan\" }\n", goodVulnerable, "sanitizer-log-path", Warning},
		{"log_path is the dir itself", logDir + "  environment: { ASAN_OPTIONS: \"log_path=/var/log/asan\" }\n", goodVulnerable, "sanitizer-log-path", Warning},
		{"log_path stderr", logDir + "  environment: { ASAN_OPTIONS: \"log_path=stderr\" }\n", goodVulnerable, "sanitizer-log-path", Warning},
		{"last log_path wins", logDir + "  environment: { ASAN_OPTIONS: \"log_path=/tmp/a,log_path=/var/log/asan/asan\" }\n", goodVulnerable, "", ""},
		{"no log_path", logDir + "  environment: { ASAN_OPTIONS: \"halt_on_error=1\" }\n", goodVulnerable, "", ""},
		{"no log_dir, no log_path check", "  environment: { ASAN_OPTIONS: \"log_path=/tmp/asan\" }\n", []string{"expect_log: x"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := (&Validator{}).Check(parse(t, seqDoc(tc.service, tc.steps...)))
			got := rules(fs)
			for _, r := range sequenceRules {
				lvl, ok := got[r]
				switch {
				case r == tc.want && !ok:
					t.Errorf("want %s, got %v", r, fs)
				case r == tc.want && lvl != tc.level:
					t.Errorf("%s is %s, want %s", r, lvl, tc.level)
				case r != tc.want && ok:
					t.Errorf("unexpected %s: %v", r, fs)
				}
			}
		})
	}
}

// A state's environment is checked for log_path too, and the finding names it.
func TestSanitizerLogPathInState(t *testing.T) {
	doc := seqDoc(logDir, goodVulnerable...) + "    environment: { ASAN_OPTIONS: \"log_path=/tmp/asan\" }\n"
	var found bool
	for _, f := range (&Validator{}).Check(parse(t, doc)) {
		if f.Rule == "sanitizer-log-path" {
			found = strings.Contains(f.Message, "states.vulnerable.environment") && f.Level == Warning
		}
	}
	if !found {
		t.Fatal("no sanitizer-log-path warning for the state's environment")
	}
}

// The sequence rules add nothing to contracts without a sequence: every
// fixture template keeps exactly the findings it had.
func TestSequenceRulesSilentWithoutSequence(t *testing.T) {
	v := &Validator{AllowUnpinned: true}
	for _, c := range fixtures(t) {
		if fs := v.sequences(c); len(fs) > 0 {
			t.Errorf("%s: %v", c.ID(), fs)
		}
	}
}

// The repository's good sequence contract validates without a sequence finding.
func TestGoodSequenceTestdata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "contract", "testdata", "good", "sequence.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	fs := (&Validator{AllowUnpinned: true}).Check(parse(t, string(data)))
	got := rules(fs)
	for _, r := range sequenceRules {
		if _, ok := got[r]; ok {
			t.Errorf("unexpected %s: %v", r, fs)
		}
	}
}
