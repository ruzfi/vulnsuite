//go:build !windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Regression for #42 item 5b: the first SIGINT cancels the command's context;
// a second one, sent while it is still tearing down, terminates the process.
func TestSecondInterruptTerminates(t *testing.T) {
	if os.Getenv("VULNSUITE_SIGNAL_CHILD") == "1" {
		ctx, _ := interruptContext()
		fmt.Println("ready")
		<-ctx.Done()
		fmt.Println("cancelled")
		time.Sleep(30 * time.Second) // a teardown that hangs
		fmt.Println("survived")
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecondInterruptTerminates$")
	cmd.Env = append(os.Environ(), "VULNSUITE_SIGNAL_CHILD=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	expect := func(want string) {
		t.Helper()
		select {
		case l := <-lines:
			if !strings.Contains(l, want) {
				t.Fatalf("child said %q, want %q", l, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("child never said %q", want)
		}
	}
	expect("ready")
	_ = cmd.Process.Signal(syscall.SIGINT)
	expect("cancelled")

	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		_ = cmd.Process.Signal(syscall.SIGINT) // the second (and, if needed, later) Ctrl-C
		select {
		case err := <-waited:
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child exited cleanly after a second SIGINT: %v", err)
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
				t.Fatalf("child did not die of SIGINT: %v", err)
			}
			return
		case <-deadline:
			_ = cmd.Process.Kill()
			t.Fatal("a second SIGINT did not terminate the process")
		case <-tick.C:
		}
	}
}
