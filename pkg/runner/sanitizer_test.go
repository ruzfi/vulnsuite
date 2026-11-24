package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// Hand-written fixtures in the formats ASan (gcc's libasan and clang's
// compiler-rt) writes to log_path.

// asanResolverUAF is the shape of the nginx resolver report from the #98
// research: the access stack, then the free and allocation stacks.
const asanResolverUAF = `=================================================================
==12==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x55d0c8a2b1c4 bp 0x7ffd5e1c2a60 sp 0x7ffd5e1c2a58
READ of size 8 at 0x602000000010 thread T0
    #0 0x55d0c8a2b1c3 in ngx_resolver_process_a src/core/ngx_resolver.c:2142
    #1 0x55d0c8a2c9f1 in ngx_resolver_process_response src/core/ngx_resolver.c:1845
    #2 0x55d0c8a2d0b2 in ngx_resolver_udp_read src/core/ngx_resolver.c:1580
    #3 0x55d0c8a4e7a0 in ngx_epoll_process_events src/event/modules/ngx_epoll_module.c:901
    #4 0x7f3a1c429d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #5 0x55d0c8a10b34 in _start (/usr/sbin/nginx+0x10b34)

0x602000000010 is located 0 bytes inside of 16-byte region [0x602000000010,0x602000000020)
freed by thread T0 here:
    #0 0x7f3a1c8b4537 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:127
    #1 0x55d0c8a1f2e0 in ngx_resolve_name_done src/core/ngx_resolver.c:520

previously allocated by thread T0 here:
    #0 0x7f3a1c8b4887 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:145
    #1 0x55d0c8a1e100 in ngx_alloc src/os/unix/ngx_alloc.c:22

SUMMARY: AddressSanitizer: heap-use-after-free src/core/ngx_resolver.c:2142 in ngx_resolver_process_a
Shadow bytes around the buggy address:
  0x0c047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c047fff8000: fa fa[fd]fd fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
==12==ABORTING
`

// clangOverflow is clang's compiler-rt format: columns, BuildId suffixes and
// an unsymbolized frame.
const clangOverflow = `=================================================================
==4711==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000015 at pc 0x5612a4c0e2b1 bp 0x7ffc3f9e2b10 sp 0x7ffc3f9e2b08
WRITE of size 1 at 0x502000000015 thread T0
    #0 0x5612a4c0e2b0 in copy_header(char*, std::string const&) /src/app/parse.cc:41:12
    #1 0x5612a4c0e5d4 in main /src/app/main.cc:17:3
    #2 0x7f8e6b229d8f  (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 490fef8403240c91833978d494d39e537409b92e)
    #3 0x5612a4b2f0a4 in _start (/app/bin/parse+0x2f0a4) (BuildId: 1a2b3c)

0x502000000015 is located 0 bytes after 5-byte region [0x502000000010,0x502000000015)
allocated by thread T0 here:
    #0 0x5612a4bc8d3d in malloc (/app/bin/parse+0xc8d3d) (BuildId: 1a2b3c)

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/app/parse.cc:41:12 in copy_header(char*, std::string const&)
==4711==ABORTING
`

const doubleFree = `==33==ERROR: AddressSanitizer: attempting double-free on 0x602000000010 in thread T0:
    #0 0x7f1 in __interceptor_free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52
    #1 0x55a in release_conn /src/srv.c:88

0x602000000010 is located 0 bytes inside of 16-byte region
SUMMARY: AddressSanitizer: double-free ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:52 in __interceptor_free
`

const segv = `AddressSanitizer:DEADLYSIGNAL
=================================================================
==9==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55e4 bp 0x7ffe sp 0x7ffe T0)
==9==The signal is caused by a READ memory access.
    #0 0x55e4 in deref /src/x.c:5
    #1 0x55f0 in main /src/x.c:9

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /src/x.c:5 in deref
==9==ABORTING
`

func TestParseSanitizerReports(t *testing.T) {
	for _, tc := range []struct {
		name        string
		text        string
		reports     int
		sanitizer   string
		kind        string
		frames      int
		first       string // StackFrame.String of the first frame
		matchKind   string
		frame       string // a frame regexp that must match ...
		frameAt     string // ... this frame
		noFrame     string // a frame regexp that must not match the first stack
		summaryText string
	}{
		{name: "gcc heap-use-after-free", text: asanResolverUAF, reports: 1, sanitizer: "AddressSanitizer",
			kind: "heap-use-after-free", frames: 6, first: "ngx_resolver_process_a ngx_resolver.c:2142",
			matchKind: "heap-use-after-free", frame: "ngx_resolver_process_(a|response)", frameAt: "ngx_resolver_process_a ngx_resolver.c:2142",
			noFrame:     "ngx_resolve_name_done|__interceptor_free", // only in the free stack
			summaryText: "heap-use-after-free at ngx_resolver_process_a ngx_resolver.c:2142"},
		{name: "frame regexp on the location", text: asanResolverUAF, reports: 1, sanitizer: "AddressSanitizer",
			kind: "heap-use-after-free", frames: 6, first: "ngx_resolver_process_a ngx_resolver.c:2142",
			matchKind: "heap-use-after-free", frame: `ngx_resolver\.c:1845`, frameAt: "ngx_resolver_process_response ngx_resolver.c:1845",
			noFrame: `ngx_alloc`},
		{name: "clang overflow, C++ frames and BuildId", text: clangOverflow, reports: 1, sanitizer: "AddressSanitizer",
			kind: "heap-buffer-overflow", frames: 4, first: "copy_header(char*, std::string const&) parse.cc:41:12",
			matchKind: "heap-buffer-overflow", frame: `^copy_header\(char\*`, frameAt: "copy_header(char*, std::string const&) parse.cc:41:12",
			noFrame: "malloc|BuildId"},
		{name: "unsymbolized frame", text: clangOverflow, reports: 1, sanitizer: "AddressSanitizer",
			kind: "heap-buffer-overflow", frames: 4, first: "copy_header(char*, std::string const&) parse.cc:41:12",
			matchKind: "heap-buffer-overflow", frame: `libc\.so\.6\+0x29d8f\)$`, frameAt: "(/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)"},
		{name: "double free by summary and description", text: doubleFree, reports: 1, sanitizer: "AddressSanitizer",
			kind: "double-free", frames: 2, first: "__interceptor_free asan_malloc_linux.cpp:52",
			matchKind: "double-free", frame: "release_conn", frameAt: "release_conn srv.c:88"},
		{name: "SEGV", text: segv, reports: 1, sanitizer: "AddressSanitizer", kind: "SEGV", frames: 2,
			first: "deref x.c:5", matchKind: "segv", frame: "main", frameAt: "main x.c:9"},
		{name: "no report", text: "==1==WARNING: AddressSanitizer failed to allocate 0x1000 bytes\nhello\n", reports: 0},
		{name: "empty", text: "", reports: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := ParseSanitizerReports(tc.text)
			if len(rs) != tc.reports {
				t.Fatalf("%d reports, want %d: %+v", len(rs), tc.reports, rs)
			}
			if tc.reports == 0 {
				return
			}
			r := rs[0]
			if r.Sanitizer != tc.sanitizer || r.Kind != tc.kind || len(r.Frames) != tc.frames {
				t.Fatalf("report = %s %s with %d frames %+v; want %s %s with %d", r.Sanitizer, r.Kind, len(r.Frames), r.Frames, tc.sanitizer, tc.kind, tc.frames)
			}
			if got := r.Frames[0].String(); got != tc.first {
				t.Errorf("first frame %q, want %q", got, tc.first)
			}
			if !r.MatchesKind(tc.matchKind) {
				t.Errorf("report does not match kind %q", tc.matchKind)
			}
			if r.MatchesKind("stack-buffer-underflow") {
				t.Error("report matches an unrelated kind")
			}
			if f, ok := r.MatchFrame(tc.frame); !ok || f.String() != tc.frameAt {
				t.Errorf("MatchFrame(%q) = %q, %v; want %q", tc.frame, f.String(), ok, tc.frameAt)
			}
			if tc.noFrame != "" {
				if f, ok := r.MatchFrame(tc.noFrame); ok {
					t.Errorf("MatchFrame(%q) matched %q outside the first stack", tc.noFrame, f.Text)
				}
			}
			if tc.summaryText != "" && r.Summary() != tc.summaryText {
				t.Errorf("Summary() = %q, want %q", r.Summary(), tc.summaryText)
			}
		})
	}
}

// Two reports in one file (halt_on_error=0), each with its own first stack;
// a report cut short (still being written) yields what is there.
func TestParseSanitizerReportsSeveralAndPartial(t *testing.T) {
	rs := ParseSanitizerReports(asanResolverUAF + segv + "==13==ERROR: AddressSanitizer: stack-use-after-return on address 0x7f\nREAD of size 4\n    #0 0x1 in f /a.c:1\n    #1 0x2 in")
	if len(rs) != 3 {
		t.Fatalf("%d reports: %+v", len(rs), rs)
	}
	if rs[0].Kind != "heap-use-after-free" || rs[1].Kind != "SEGV" || rs[2].Kind != "stack-use-after-return" {
		t.Fatalf("kinds %s, %s, %s", rs[0].Kind, rs[1].Kind, rs[2].Kind)
	}
	if len(rs[1].Frames) != 2 || rs[1].Frames[0].Func != "deref" {
		t.Fatalf("second report's frames %+v", rs[1].Frames)
	}
	if len(rs[2].Frames) != 2 || rs[2].Frames[0].String() != "f a.c:1" {
		t.Fatalf("partial report's frames %+v", rs[2].Frames)
	}
	// Other sanitizers with the same header parse too.
	ub := ParseSanitizerReports("==5==ERROR: LeakSanitizer: detected memory leaks\n\nDirect leak of 7 byte(s)\n    #0 0x1 in malloc\n")
	if len(ub) != 1 || ub[0].Sanitizer != "LeakSanitizer" || ub[0].Kind != "leak" || !ub[0].MatchesKind("leak") || !ub[0].MatchesKind("detected") {
		t.Fatalf("LeakSanitizer report %+v", ub)
	}
	if !strings.Contains(rs[0].Description, "on address 0x602000000010") {
		t.Errorf("description %q", rs[0].Description)
	}
}

// ThreadSanitizer and MemorySanitizer head their reports with WARNING, and
// LeakSanitizer's SUMMARY ("64 byte(s) leaked") names no bug class (#136).
func TestParseWarningSanitizersAndLeakSummary(t *testing.T) {
	for _, tc := range []struct {
		name, text, sanitizer, kind, frame string
		match                              []string
	}{
		{"tsan data race",
			"==================\nWARNING: ThreadSanitizer: data race (pid=7)\n  Write of size 4 at 0x7b04 by thread T2:\n    #0 worker /src/race.c:12:5 (race+0x1234)\n    #1 <null> <null> (libtsan.so.2+0x5d6)\n\n  Previous read of size 4 at 0x7b04 by thread T1:\n    #0 reader /src/race.c:20 (race+0x99)\n\nSUMMARY: ThreadSanitizer: data race /src/race.c:12:5 in worker\n",
			"ThreadSanitizer", "data-race", "worker race.c:12:5", []string{"data-race", "race"}},
		{"tsan heap-use-after-free",
			"WARNING: ThreadSanitizer: heap-use-after-free (pid=7)\nSUMMARY: ThreadSanitizer: heap-use-after-free /src/x.c:3 in f\n",
			"ThreadSanitizer", "heap-use-after-free", "", []string{"heap-use-after-free"}},
		{"tsan cut short",
			"WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock) (pid=7)\n",
			"ThreadSanitizer", "lock-order-inversion", "", []string{"lock-order-inversion"}},
		{"msan",
			"==9==WARNING: MemorySanitizer: use-of-uninitialized-value\n    #0 0x4a1 in main /src/m.c:8:7\n\nSUMMARY: MemorySanitizer: use-of-uninitialized-value /src/m.c:8:7 in main\n",
			"MemorySanitizer", "use-of-uninitialized-value", "main m.c:8:7", []string{"use-of-uninitialized-value"}},
		{"lsan summary without a class",
			"==5==ERROR: LeakSanitizer: detected memory leaks\n\nDirect leak of 64 byte(s) in 1 object(s) allocated from:\n    #0 0x1 in malloc\n\nSUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).\n",
			"LeakSanitizer", "leak", "malloc", []string{"leak", "detected"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := ParseSanitizerReports(tc.text)
			if len(rs) != 1 {
				t.Fatalf("%d reports: %+v", len(rs), rs)
			}
			r := rs[0]
			if r.Sanitizer != tc.sanitizer || r.Kind != tc.kind {
				t.Fatalf("sanitizer %q kind %q, want %q %q", r.Sanitizer, r.Kind, tc.sanitizer, tc.kind)
			}
			for _, k := range tc.match {
				if !r.MatchesKind(k) {
					t.Errorf("MatchesKind(%q) = false", k)
				}
			}
			if tc.frame != "" && (len(r.Frames) == 0 || r.Frames[0].String() != tc.frame) {
				t.Errorf("frames %+v, want first %q", r.Frames, tc.frame)
			}
		})
	}
	// Other sanitizers' WARNING lines are notices, not reports.
	for _, notice := range []string{
		"==1==WARNING: AddressSanitizer failed to allocate 0x10000 bytes",
		"==1==WARNING: ASan is ignoring requested __asan_handle_no_return",
		"WARNING: AddressSanitizer: something odd",
	} {
		if rs := ParseSanitizerReports(notice + "\n"); len(rs) != 0 {
			t.Errorf("%q parsed as a report: %+v", notice, rs)
		}
	}
}

func TestLinesAfter(t *testing.T) {
	for _, tc := range []struct {
		name, before, now, want string
	}{
		{"appended", "a\nb\n", "a\nb\nc\nd\n", "c\nd\n"},
		{"nothing new", "a\nb\n", "a\nb\n", ""},
		{"tail window moved", "a\nb\nc\n", "b\nc\nd\n", "d\n"},
		{"no overlap: all new", "a\nb\n", "x\ny\n", "x\ny\n"},
		{"incomplete last line completed", "a\nb", "a\nbc\nd\n", "c\nd\n"},
		{"empty before", "", "a\n", "a\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := linesAfter(lastLines(tc.before, logTailLines), tc.now); got != tc.want {
				t.Errorf("linesAfter = %q, want %q", got, tc.want)
			}
		})
	}
}

// #146: UndefinedBehaviorSanitizer reports ("file:line: runtime error: ...",
// with or without a stack, and a SUMMARY alone) are parsed, so
// expect_sanitizer: none fails over them under -fsanitize=address,undefined.
func TestParseUBSanReports(t *testing.T) {
	const withStack = "/src/calc.c:12:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n" +
		"    #0 0x55d1 in add /src/calc.c:12:9\n    #1 0x55d2 in main /src/calc.c:30:3\n\n" +
		"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/calc.c:12:9 in \n"
	const bare = "/src/shift.c:4:14: runtime error: shift exponent 40 is too large for 32-bit type 'int'\n"
	const summaryOnly = "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/idx.c:7:3 in \n"
	const goPanic = "panic: runtime error: index out of range [5] with length 3\n"

	rs := ParseSanitizerReports(asanResolverUAF + withStack + bare + summaryOnly + goPanic)
	if len(rs) != 4 {
		t.Fatalf("%d reports: %+v", len(rs), rs)
	}
	if rs[0].Sanitizer != "AddressSanitizer" || rs[0].Kind != "heap-use-after-free" {
		t.Fatalf("the ASan report before the UBSan ones changed: %+v", rs[0])
	}
	ub := rs[1]
	if ub.Sanitizer != "UndefinedBehaviorSanitizer" || ub.Kind != "undefined-behavior" || !strings.HasPrefix(ub.Description, "signed integer overflow: 2147483647") {
		t.Fatalf("with stack: %+v", ub)
	}
	for _, k := range []string{"undefined-behavior", "signed-integer-overflow", "overflow"} {
		if !ub.MatchesKind(k) {
			t.Errorf("MatchesKind(%q) = false", k)
		}
	}
	if ub.MatchesKind("heap-use-after-free") {
		t.Error("a UBSan report matched an ASan kind")
	}
	if len(ub.Frames) != 2 || ub.Frames[0].String() != "add calc.c:12:9" {
		t.Fatalf("with stack frames: %+v", ub.Frames)
	}
	if f, ok := ub.MatchFrame("^add "); !ok || f.Func != "add" {
		t.Fatalf("MatchFrame: %+v %v", f, ok)
	}
	// Without print_stacktrace the header's location is the only frame.
	b := rs[2]
	if b.Kind != "undefined-behavior" || !b.MatchesKind("shift-exponent") || len(b.Frames) != 1 || b.Frames[0].String() != "shift.c:4:14" {
		t.Fatalf("bare: %+v", b)
	}
	if _, ok := b.MatchFrame(`shift\.c:4`); !ok {
		t.Fatal("bare report's location does not match a frame regexp")
	}
	if s := b.Summary(); s != "undefined-behavior at shift.c:4:14" {
		t.Fatalf("summary %q", s)
	}
	// A SUMMARY alone (report_error_type, or the header cut off).
	so := rs[3]
	if so.Sanitizer != "UndefinedBehaviorSanitizer" || so.Kind != "undefined-behavior" || len(so.Frames) != 1 || so.Frames[0].Location != "/src/idx.c:7:3" {
		t.Fatalf("summary only: %+v", so)
	}
	if rs := ParseSanitizerReports(goPanic); len(rs) != 0 {
		t.Fatalf("a Go panic parsed as a UBSan report: %+v", rs)
	}
}

// #146: under -fsanitize=address,undefined, a UBSan report written during
// the attempt fails expect_sanitizer: none, and a positive step can expect it.
func TestSequenceUBSanReport(t *testing.T) {
	const report = "/src/calc.c:12:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n" +
		"SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/calc.c:12:9 in \n"
	f := newSeqFix(t)
	pid := 40
	f.setExec(func(_, cmd string) (int, string, error) {
		if cmd == "/trigger fire" {
			pid++
			f.report(pid, report)
		}
		return 0, "", nil
	})
	r := f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectNone())})
	if r.OK || outcomes(r) != "fail" || !strings.Contains(r.Detail, "sanitizer report: undefined-behavior at calc.c:12:9") {
		t.Fatalf("none passed over a UBSan report: %+v", r)
	}
	r = f.run(context.Background(), &contract.SequenceProbe{Steps: raceSteps(expectHit("signed-integer-overflow", `calc\.c:12`))})
	if !r.OK || outcomes(r) != "hit" {
		t.Fatalf("positive UBSan step: %+v", r)
	}
}
