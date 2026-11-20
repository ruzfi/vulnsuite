package runner

import (
	"path"
	"regexp"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// SanitizerReport is one report parsed from a sanitizer log (ASan's format;
// other sanitizers that write the same `ERROR: <Name>Sanitizer: <kind>` header
// parse the same way).
type SanitizerReport struct {
	// Sanitizer is the runtime's name, e.g. "AddressSanitizer".
	Sanitizer string
	// Kind is the bug class: the SUMMARY line's (e.g. "heap-use-after-free",
	// "double-free") when the report has one, else the first word of the
	// ERROR line's description.
	Kind string
	// Description is the ERROR line after "<Sanitizer>: ".
	Description string
	// Frames is the report's first stack (the faulting access), in order.
	Frames []StackFrame
	// summaryKind is the SUMMARY line's bug class, "" when there is none.
	summaryKind string
}

// StackFrame is one frame of a sanitizer stack trace.
type StackFrame struct {
	// Func is the function ("" when the frame is not symbolized).
	Func string
	// Location is the source position (src/x.c:12 or src/x.c:12:5) or the
	// module and offset ("(/lib/libc.so.6+0x29d90)").
	Location string
	// Text is the frame after its address with a leading "in " removed:
	// "Func Location". A frame regexp is matched against it.
	Text string
}

var (
	sanErrorRe   = regexp.MustCompile(`ERROR: ([A-Za-z]*Sanitizer): (.*)$`)
	sanSummaryRe = regexp.MustCompile(`^SUMMARY: ([A-Za-z]*Sanitizer): (\S+)`)
	sanFrameRe   = regexp.MustCompile(`^\s*#\d+\s+0x[0-9a-fA-F]+\s*(.*)$`)
	sanBuildIDRe = regexp.MustCompile(`\s+\(BuildId: [0-9a-fA-F]+\)\s*$`)
)

// ParseSanitizerReports reads every report in a sanitizer log: each starts at
// an `ERROR: <Sanitizer>: <description>` line (the `==pid==` prefix is
// optional), and its first stack is the first run of `#N 0x...` frame lines
// after it, up to the first line that is not a frame (the blank line before
// the next section). A report cut short (still being written, or capped)
// yields what is there.
func ParseSanitizerReports(text string) []SanitizerReport {
	var out []SanitizerReport
	var cur *SanitizerReport
	inStack, stackDone := false, false
	flush := func() {
		if cur != nil {
			if cur.summaryKind != "" {
				cur.Kind = cur.summaryKind
			}
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := sanErrorRe.FindStringSubmatch(line); m != nil {
			flush()
			desc := strings.TrimSpace(m[2])
			kind := ""
			if f := strings.Fields(desc); len(f) > 0 {
				kind = f[0]
			}
			cur = &SanitizerReport{Sanitizer: m[1], Kind: kind, Description: desc}
			inStack, stackDone = false, false
			continue
		}
		if cur == nil {
			continue
		}
		if m := sanSummaryRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			cur.summaryKind = m[2]
			continue
		}
		if stackDone {
			continue
		}
		if m := sanFrameRe.FindStringSubmatch(line); m != nil {
			inStack = true
			cur.Frames = append(cur.Frames, parseFrame(m[1]))
			continue
		}
		if inStack {
			stackDone = true // the first stack ends at its first non-frame line
		}
	}
	flush()
	return out
}

// parseFrame splits a frame's text after its address: "in func loc",
// "in func(args) loc", or an unsymbolized "(module+0xoff)".
func parseFrame(s string) StackFrame {
	s = strings.TrimSpace(sanBuildIDRe.ReplaceAllString(s, ""))
	s = strings.TrimPrefix(s, "in ")
	f := StackFrame{Text: s}
	if i := strings.LastIndexByte(s, ' '); i >= 0 {
		f.Func, f.Location = strings.TrimSpace(s[:i]), s[i+1:]
	} else if strings.HasPrefix(s, "(") {
		f.Location = s
	} else {
		f.Func = s
	}
	return f
}

// String is the frame as a report detail shows it: the function and the
// file's base name with its line, e.g. "ngx_resolver_process_a ngx_resolver.c:2142".
func (f StackFrame) String() string {
	loc := f.Location
	if loc != "" && !strings.HasPrefix(loc, "(") {
		loc = path.Base(loc)
	}
	return strings.TrimSpace(f.Func + " " + loc)
}

// MatchesKind reports whether the report is of bug class kind: its SUMMARY
// class, or a word of its ERROR description before the address ("attempting
// double-free on 0x..." is a double-free). Case does not matter.
func (r SanitizerReport) MatchesKind(kind string) bool {
	if strings.EqualFold(r.Kind, kind) || strings.EqualFold(r.summaryKind, kind) {
		return true
	}
	for _, w := range strings.Fields(r.Description) {
		if w == "on" || w == "at" || strings.HasPrefix(w, "0x") || strings.HasPrefix(w, "(") {
			break
		}
		if strings.EqualFold(w, kind) {
			return true
		}
	}
	return false
}

// MatchFrame returns the first frame of the first stack that matches the Go
// regexp frame (dot matches newline, as in every probe pattern); an empty
// frame matches the first frame. ok is false when none matches.
func (r SanitizerReport) MatchFrame(frame string) (StackFrame, bool) {
	if frame == "" {
		if len(r.Frames) == 0 {
			return StackFrame{}, true
		}
		return r.Frames[0], true
	}
	for _, f := range r.Frames {
		if probes.MatchDotAll(frame, f.Text) {
			return f, true
		}
	}
	return StackFrame{}, false
}

// Summary is the report as one detail phrase: "heap-use-after-free at main uaf.c:12".
func (r SanitizerReport) Summary() string {
	if len(r.Frames) == 0 {
		return r.Kind
	}
	return r.Kind + " at " + r.Frames[0].String()
}
