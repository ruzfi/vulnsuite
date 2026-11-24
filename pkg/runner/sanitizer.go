package runner

import (
	"path"
	"regexp"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/probes"
)

// SanitizerReport is one report parsed from a sanitizer log: an
// `ERROR: <Name>Sanitizer: <description>` header (AddressSanitizer,
// LeakSanitizer, and others in the same format), or the
// `WARNING: ThreadSanitizer: ...` / `WARNING: MemorySanitizer: ...` header
// those two print, or an UndefinedBehaviorSanitizer
// `file:line:col: runtime error: <description>` line (or its SUMMARY alone).
type SanitizerReport struct {
	// Sanitizer is the runtime's name, e.g. "AddressSanitizer".
	Sanitizer string
	// Kind is the bug class: the SUMMARY line's (e.g. "heap-use-after-free",
	// "double-free", "data-race") when the report has one, else taken from
	// the header's description: its first word, its leading words joined by
	// "-" for ThreadSanitizer ("data race" is "data-race"), "leak" for
	// LeakSanitizer, and "undefined-behavior" for UndefinedBehaviorSanitizer.
	Kind string
	// Description is the ERROR line after "<Sanitizer>: " (for UBSan, the
	// text after "runtime error: ").
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
	// ThreadSanitizer and MemorySanitizer head their reports with WARNING;
	// other sanitizers' WARNING lines are notices, not reports.
	sanErrorRe   = regexp.MustCompile(`(?:ERROR: ([A-Za-z]*Sanitizer)|WARNING: (ThreadSanitizer|MemorySanitizer)): (.*)$`)
	sanSummaryRe = regexp.MustCompile(`^SUMMARY: ([A-Za-z]*Sanitizer): (.*)$`)
	sanWordRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z_-]*$`)
	// A frame: "#0 0x4a1 in f /src/x.c:12" (ASan, MSan), or without the
	// address, "#0 f /src/x.c:12 (bin+0x4a1)" (ThreadSanitizer).
	sanFrameRe   = regexp.MustCompile(`^\s*#\d+\s+(?:0x[0-9a-fA-F]+(?:\s+|$))?(.*)$`)
	sanModuleRe  = regexp.MustCompile(`\s+\([^()\s]+\+0x[0-9a-fA-F]+\)$`)
	sanBuildIDRe = regexp.MustCompile(`\s+\(BuildId: [0-9a-fA-F]+\)\s*$`)
	// UndefinedBehaviorSanitizer heads a report with the source location:
	// "/src/x.c:12:5: runtime error: signed integer overflow: ...". The
	// location must look like one, so a Go "panic: runtime error:" is not it.
	ubsanErrorRe = regexp.MustCompile(`^\s*(?:==\d+==\s*)?(\S+:\d+(?::\d+)?|<unknown>): runtime error: (.*)$`)
)

// ubsan is UndefinedBehaviorSanitizer's name in its SUMMARY line.
const ubsan = "UndefinedBehaviorSanitizer"

// ParseSanitizerReports reads every report in a sanitizer log: each starts at
// an `ERROR: <Sanitizer>: <description>` line, or a ThreadSanitizer or
// MemorySanitizer `WARNING: <Sanitizer>: <description>` line (the `==pid==`
// prefix is optional), or an UndefinedBehaviorSanitizer
// `<file:line[:col]>: runtime error: <description>` line, and its first stack is the first run of `#N 0x...` frame lines
// after it, up to the first line that is not a frame (the blank line before
// the next section). A report cut short (still being written, or capped)
// yields what is there.
func ParseSanitizerReports(text string) []SanitizerReport {
	var out []SanitizerReport
	var cur *SanitizerReport
	inStack, stackDone := false, false
	// UBSan prints a stack only with print_stacktrace=1; without one, its
	// header's source location is the report's only frame.
	var ubsanLoc string
	flush := func() {
		if cur != nil {
			if cur.summaryKind != "" {
				cur.Kind = cur.summaryKind
			}
			if cur.Sanitizer == ubsan && len(cur.Frames) == 0 && ubsanLoc != "" && ubsanLoc != "<unknown>" {
				cur.Frames = []StackFrame{{Location: ubsanLoc, Text: ubsanLoc}}
			}
			out = append(out, *cur)
		}
		cur, ubsanLoc = nil, ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := sanErrorRe.FindStringSubmatch(line); m != nil {
			flush()
			san := m[1] + m[2]
			desc := strings.TrimSpace(m[3])
			cur = &SanitizerReport{Sanitizer: san, Kind: headerKind(san, desc), Description: desc}
			inStack, stackDone = false, false
			continue
		}
		if m := ubsanErrorRe.FindStringSubmatch(line); m != nil {
			flush()
			desc := strings.TrimSpace(m[2])
			cur = &SanitizerReport{Sanitizer: ubsan, Kind: headerKind(ubsan, desc), Description: desc}
			ubsanLoc = m[1]
			inStack, stackDone = false, false
			continue
		}
		summary := sanSummaryRe.FindStringSubmatch(strings.TrimSpace(line))
		if summary != nil && summary[1] == ubsan {
			loc := "" // "undefined-behavior /src/x.c:12:5 in"
			if f := strings.Fields(summary[2]); len(f) > 1 {
				loc = f[1]
			}
			if cur == nil || cur.Sanitizer != ubsan || cur.summaryKind != "" || (loc != "" && loc != ubsanLoc) {
				// A UBSan SUMMARY without its own header (the header cut
				// off) is a report of its own, never a second summary of
				// the report before it or one about another location.
				flush()
				cur = &SanitizerReport{Sanitizer: ubsan, Kind: headerKind(ubsan, "")}
				ubsanLoc = loc
				inStack, stackDone = false, true
			}
		}
		if cur == nil {
			continue
		}
		if m := summary; m != nil {
			// "heap-use-after-free /src/x.c:12 in f", "data race ...";
			// LeakSanitizer's "64 byte(s) leaked ..." names no class.
			words := 1
			if m[1] == "ThreadSanitizer" {
				words = -1
			}
			cur.summaryKind = phraseKind(m[2], words)
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

// headerKind is a report's bug class from its header's description, for a
// report without a SUMMARY line (cut short, or a sanitizer that writes none).
func headerKind(sanitizer, desc string) string {
	switch sanitizer {
	case "LeakSanitizer":
		return "leak" // "detected memory leaks"
	case "ThreadSanitizer":
		return phraseKind(desc, -1) // "data race (pid=7)"
	case ubsan:
		return "undefined-behavior" // as its SUMMARY says
	}
	return phraseKind(desc, 1)
}

// phraseKind joins the leading words of s with "-", at most max of them (all
// when max < 0): a word is letters, digits after the first, "-" and "_". It
// stops at the first other token (a path, a number, "(pid=7)") and at the
// words "on", "at" and "in" ("SEGV on unknown address"). "" when s does not
// start with a word.
func phraseKind(s string, max int) string {
	var words []string
	for _, w := range strings.Fields(s) {
		if max >= 0 && len(words) == max {
			break
		}
		if !sanWordRe.MatchString(w) || w == "on" || w == "at" || w == "in" {
			break
		}
		words = append(words, w)
	}
	return strings.Join(words, "-")
}

// parseFrame splits a frame's text after its address: "in func loc",
// "in func(args) loc", or an unsymbolized "(module+0xoff)".
func parseFrame(s string) StackFrame {
	s = strings.TrimSpace(sanBuildIDRe.ReplaceAllString(s, ""))
	s = strings.TrimPrefix(s, "in ")
	// ThreadSanitizer adds the module and offset after the source location:
	// "worker /src/race.c:12:5 (race+0x1234)". Keep them only when they are
	// the whole location.
	if loc := sanModuleRe.ReplaceAllString(s, ""); loc != s && strings.Contains(loc, " ") {
		s = loc
	}
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
// double-free on 0x..." is a double-free). For UndefinedBehaviorSanitizer
// the description's leading phrase joined by "-" matches too ("signed
// integer overflow: ..." is a signed-integer-overflow, "shift exponent 40 is
// too large" a shift-exponent). Case does not matter.
func (r SanitizerReport) MatchesKind(kind string) bool {
	if strings.EqualFold(r.Kind, kind) || strings.EqualFold(r.summaryKind, kind) {
		return true
	}
	if r.Sanitizer == ubsan {
		phrase, _, _ := strings.Cut(r.Description, ":")
		if p := phraseKind(phrase, -1); p != "" && strings.EqualFold(p, kind) {
			return true
		}
	}
	for _, w := range strings.Fields(r.Description) {
		if w == "on" || w == "at" || strings.HasPrefix(w, "0x") || strings.HasPrefix(w, "(") {
			break
		}
		if strings.EqualFold(strings.TrimSuffix(w, ":"), kind) {
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
