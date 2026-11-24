package probes

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// A read size beyond what a contract allows is clamped instead of allocating
// it (or panicking in make for a huge one), and a negative one reads nothing
// (#145).
func TestReadUntilClampsMax(t *testing.T) {
	for _, max := range []int{1_000_000_000_000_000, 2_000_000_000, -1} {
		client, server := net.Pipe()
		go func() {
			_, _ = server.Write(bytes.Repeat([]byte("a"), maxRead+10))
			_ = server.Close()
		}()
		got := readUntil(client, max, "", time.Now().Add(2*time.Second))
		_ = client.Close()
		want := maxRead
		if max < 0 {
			want = 0
		}
		if len(got) != want {
			t.Errorf("max %d: read %d bytes, want %d", max, len(got), want)
		}
	}
}
