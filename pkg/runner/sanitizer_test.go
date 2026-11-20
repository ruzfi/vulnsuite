package runner

import (
	"strings"
	"testing"
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
	if len(ub) != 1 || ub[0].Sanitizer != "LeakSanitizer" || ub[0].Kind != "detected" || !ub[0].MatchesKind("detected") {
		t.Fatalf("LeakSanitizer report %+v", ub)
	}
	if !strings.Contains(rs[0].Description, "on address 0x602000000010") {
		t.Errorf("description %q", rs[0].Description)
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
