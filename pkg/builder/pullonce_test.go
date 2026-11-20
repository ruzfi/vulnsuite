package builder

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// Parallel jobs sharing a base image pull it once. Both apache states are
// overlay builds FROM httpd:2.4.49; each used to see it missing and pull it,
// which also made the CLI's build test flaky on slower runners.
func TestResolveAllPullsSharedBaseOnce(t *testing.T) {
	fe := enginetest.New()
	var inflight, overlap atomic.Int32
	fe.PullFn = func(ref string) error {
		if inflight.Add(1) > 1 {
			overlap.Store(1)
		}
		time.Sleep(150 * time.Millisecond) // a pull takes a while
		inflight.Add(-1)
		return nil
	}
	c, err := store(t).LoadSelector("apache-httpd-2.4.49-cve-2021-41773")
	if err != nil {
		t.Fatal(err)
	}
	jobs := []Job{{Contract: c, State: "vulnerable"}, {Contract: c, State: "patched"}}
	for _, o := range New(fe).ResolveAll(context.Background(), jobs, 2, Options{Pull: true}, nil) {
		if o.Err != nil {
			t.Fatalf("%s/%s: %v", o.Job.Contract.ID(), o.Job.State, o.Err)
		}
	}
	n := 0
	for _, p := range fe.Pulls {
		if p == "httpd:2.4.49" {
			n++
		}
	}
	if n != 1 || overlap.Load() != 0 {
		t.Fatalf("httpd:2.4.49 pulled %d times (overlapping=%v); pulls %v", n, overlap.Load() == 1, fe.Pulls)
	}
}
