// Command vulnsuite builds and runs reproducible vulnerable targets (and their
// patched twins) from community templates, in a verified state.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ruzfi/vulnsuite/internal/cli"
)

func main() {
	ctx, stop := interruptContext()
	code := cli.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// interruptContext is cancelled by the first SIGINT/SIGTERM. That first signal
// also releases the handler, so a second one terminates the process even while
// the command is still tearing down.
func interruptContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx, stop
}
