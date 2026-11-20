// Package conformance holds the behaviour suite every engine.Engine
// implementation must pass: engine/moby (the official SDK), engine/docker (the
// built-in API client) and enginetest.Fake (the in-memory engine the builder,
// runner and CLI tests run on).
//
// The suite is test-only. The two real clients are driven against one shared
// httptest daemon stub that speaks the subset of the Docker Engine API the
// cases need; the fake runs directly. A case that one implementation is known
// to fail, with the fix in an open pull request, is skipped for that
// implementation with a message naming the pull request, so it can be enabled
// once that merges.
package conformance
