package runner

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// CauseProbe is the skip cause of a target whose requires.probe exited non-zero.
const CauseProbe = "probe"

// SkipError is returned by Run when the target cannot run on this host and
// that only became known while running it (requires.probe). It is a skip,
// not a failure.
type SkipError struct {
	ID       string
	Decision Decision
}

func (e *SkipError) Error() string { return fmt.Sprintf("skip %s: %s", e.ID, e.Decision.Reason) }

// AsSkip reports whether err is (or wraps) a SkipError, and returns it.
func AsSkip(err error) (*SkipError, bool) {
	var s *SkipError
	ok := errors.As(err, &s)
	return s, ok
}

// RequiresProbe runs c's requires.probe in image, the image of state already
// built or pulled for platform ("" = native), before anything of the target
// starts. It returns a native decision when there is no probe or it exits 0,
// and a skip (cause "probe", reason requires.probe.reason plus the exit code
// and output) when it exits non-zero. Not being able to run it (the image has
// no /bin/sh, the timeout runs out, an engine error) is an error: that is a
// broken template or daemon, not a host that lacks something.
//
// The probe runs as `/bin/sh -c <run>` with the image's entrypoint replaced,
// the service's user and environment, no network, no capabilities and none of
// the service's devices.
func RequiresProbe(ctx context.Context, eng engine.Engine, c *contract.Contract, state, image, platform string) (Decision, error) {
	p := c.Requires.Probe
	if p == nil {
		return Decision{Action: ActionNative}, nil
	}
	st, err := c.State(state)
	if err != nil {
		return Decision{}, err
	}
	spec := engine.ContainerSpec{
		Image:      image,
		Entrypoint: []string{"/bin/sh", "-c"},
		Cmd:        []string{p.Run},
		User:       c.Service.User,
		Env:        mergeEnv(c.Service.Environment, st.Environment),
		Platform:   platform,
	}
	out, code, err := runProbeContainer(ctx, eng, spec, p.TimeoutDuration())
	if err != nil {
		return Decision{}, fmt.Errorf("requires.probe %q: %w", p.Run, err)
	}
	if code == 0 {
		return Decision{Action: ActionNative}, nil
	}
	detail := fmt.Sprintf("requires.probe %q exited %d", p.Run, code)
	if o := strings.TrimSpace(tail(out, 300)); o != "" {
		detail += ": " + strings.Join(strings.Fields(o), " ")
	}
	return Decision{Action: ActionSkip, Cause: CauseProbe, Reason: fmt.Sprintf("%s (%s)", p.Reason, detail)}, nil
}
