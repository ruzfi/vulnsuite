package cli

import (
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// info lists every verify probe; a sequence is summarised by its attempts and
// step kinds, and an unknown (empty) probe falls back to its kind.
func TestProbeSummaryKinds(t *testing.T) {
	seq := contract.Probe{Sequence: &contract.SequenceProbe{Attempts: 3, Steps: []contract.SequenceStep{
		{Exec: &contract.SequenceExec{ExecProbe: contract.ExecProbe{Run: "/t setup"}, Container: "driver"}},
		{Freeze: &contract.FreezeStep{}},
		{Resume: &contract.ResumeStep{}},
		{ExpectSanitizer: &contract.ExpectSanitizer{None: true}},
	}}}
	for _, tc := range []struct {
		p    contract.Probe
		want string
	}{
		{seq, "sequence x3 (min_hits 1): exec, freeze, resume, expect_sanitizer"},
		{contract.Probe{Exec: &contract.ExecProbe{Run: "id", StdoutMatches: "root"}}, `exec "id" stdout ~ /root/`},
		{contract.Probe{}, ""},
	} {
		if got := probeSummary(tc.p); got != tc.want {
			t.Errorf("probeSummary = %q, want %q", got, tc.want)
		}
	}
}
