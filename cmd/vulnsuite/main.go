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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
