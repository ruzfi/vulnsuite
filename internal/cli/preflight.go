package cli

import (
	"context"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/runner"
)

// preflighter decides targets' requires against the daemon for one command.
// The daemon's CPU flags take a container to read, so they are read lazily:
// only once a selected target sets requires.cpu_flags and meets everything
// else, and then once for the whole invocation.
type preflighter struct {
	ctx  context.Context
	g    *Global
	eng  engine.Engine
	host engine.HostInfo
	// noPull: the probe image must already be present (-no-pull).
	noPull bool
	// noRead leaves the flags unread (-ignore-requires: the decision is
	// overridden anyway, so a probe container would be wasted).
	noRead bool
}

func (p *preflighter) decide(req contract.Requires) runner.Decision {
	if !p.noRead && runner.NeedsCPUFlags(req, p.host) {
		p.g.printf("reading the daemon's CPU flags (requires.cpu_flags)...\n")
		p.host = runner.WithCPUFlags(p.ctx, p.eng, p.host, runner.HostProbeOptions{NoPull: p.noPull, Progress: p.g.progress()})
		if p.host.CPUFlagsError != "" {
			p.g.errorf("warning: could not read the daemon's CPU flags: %s\n  targets that set requires.cpu_flags are skipped; -ignore-requires runs them anyway\n", p.host.CPUFlagsError)
		}
	}
	return runner.Preflight(req, p.host)
}
