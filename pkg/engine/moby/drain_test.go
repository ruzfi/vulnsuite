package moby

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/jsonstream"
)

// stream yields msgs to the callback until it asks to stop.
func stream(msgs ...jsonstream.Message) func(func(streamMessage, error) bool) {
	return func(yield func(streamMessage, error) bool) {
		for _, m := range msgs {
			if !yield(streamMessage{Message: m}, nil) {
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

// Regression for #92 item 2: a stream whose failure arrives only as the
// legacy top-level "error" string (which jsonstream.Message no longer has) or
// only as "errorDetail" must fail, for pulls/pushes and builds alike.
func TestStreamErrorForms(t *testing.T) {
	for name, line := range map[string]string{
		"error only":       `{"error":"boom"}`,
		"errorDetail only": `{"errorDetail":{"message":"boom"}}`,
		"both":             `{"error":"boom","errorDetail":{"message":"boom"}}`,
	} {
		body := `{"status":"Pulling fs layer","id":"a"}` + "\n" + line + "\n" + `{"status":"Done"}` + "\n"
		err := drain(context.Background(), messages(context.Background(), io.NopCloser(strings.NewReader(body))), nil)
		if err == nil || err.Error() != "boom" {
			t.Errorf("%s: drain = %v, want boom", name, err)
		}
		build := `{"stream":"Step 1/1 : FROM scratch\n"}` + "\n" + line + "\n"
		if err := drainReader(strings.NewReader(build), nil); err == nil || err.Error() != "boom" {
			t.Errorf("%s: drainReader = %v, want boom", name, err)
		}
	}
	if err := drain(context.Background(), messages(context.Background(), io.NopCloser(strings.NewReader(`{"status":"Done"}`))), nil); err != nil {
		t.Errorf("clean stream: %v", err)
	}
}
