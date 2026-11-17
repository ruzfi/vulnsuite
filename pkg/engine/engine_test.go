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
