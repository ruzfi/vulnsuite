package engine

import (
	"io"
	"strings"
	"testing"
)

func TestCappedBufferDrainsPastCap(t *testing.T) {
	b := &CappedBuffer{Max: 10}
	n, err := io.Copy(b, strings.NewReader(strings.Repeat("x", 1000)))
	if err != nil || n != 1000 {
		t.Fatalf("copy should consume everything: n=%d err=%v", n, err)
	}
	if b.String() != strings.Repeat("x", 10) || !b.Truncated {
		t.Fatalf("kept %q truncated=%v", b.String(), b.Truncated)
	}
	small := &CappedBuffer{Max: 10}
	_, _ = small.Write([]byte("abc"))
	if small.String() != "abc" || small.Truncated {
		t.Fatalf("small: %q %v", small.String(), small.Truncated)
	}
}

func TestPlatformMatches(t *testing.T) {
	cases := []struct {
		want, os, arch, variant string
		ok                      bool
	}{
		{"", "", "", "", true},
		{"", "linux", "arm64", "v8", true},
		{"linux/amd64", "linux", "amd64", "", true},
		{"linux/amd64", "linux", "x86_64", "", true},
		{"linux/amd64", "linux", "arm64", "v8", false},
		{"linux/amd64", "", "", "", false}, // unknown arch never satisfies an explicit platform
		{"linux/arm64", "linux", "aarch64", "", true},
		{"linux/arm64/v8", "linux", "arm64", "", true},
		{"linux/arm/v7", "linux", "arm", "v6", false},
		{"linux/arm/v7", "linux", "arm", "v7", true},
		{"windows/amd64", "linux", "amd64", "", false},
	}
	for _, c := range cases {
		if got := PlatformMatches(c.want, c.os, c.arch, c.variant); got != c.ok {
			t.Errorf("PlatformMatches(%q, %q, %q, %q) = %v, want %v", c.want, c.os, c.arch, c.variant, got, c.ok)
		}
	}
}
