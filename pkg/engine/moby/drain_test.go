package moby

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/jsonstream"
)

// stream yields msgs to the callback until it asks to stop.
func stream(msgs ...jsonstream.Message) func(func(jsonstream.Message, error) bool) {
	return func(yield func(jsonstream.Message, error) bool) {
		for _, m := range msgs {
			if !yield(m, nil) {
				return
			}
		}
	}
}

// Regression for #42 item 6: a pull/push stream cut short by cancellation must
// not be reported as success.
func TestDrainReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := drain(ctx, stream(jsonstream.Message{Status: "Pulling fs layer"}, jsonstream.Message{Status: "Download complete"}), nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled drain returned %v, want context.Canceled", err)
	}
	// The iterator giving up on a cancelled ctx without yielding anything.
	if err := drain(ctx, stream(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("empty cancelled drain returned %v, want context.Canceled", err)
	}
	if err := drain(context.Background(), stream(jsonstream.Message{Status: "done"}), nil); err != nil {
		t.Fatalf("complete stream: %v", err)
	}
}
