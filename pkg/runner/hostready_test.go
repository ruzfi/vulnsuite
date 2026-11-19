package runner

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/builder"
	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
)

// In host mode the published port is held by Docker's port proxy, which
// accepts connections before the service listens in the container and closes
// them at once. A tcp healthcheck must wait for the service, not pass on the
// proxy's accept, or seeds and verify race the service's startup.
func TestHostModeTCPReadinessWaitsBehindPortProxy(t *testing.T) {
	var listening atomic.Bool
	fe := enginetest.New()
	fe.StartFn = func(spec engine.ContainerSpec) error {
		l, err := net.Listen("tcp", net.JoinHostPort(spec.Ports[0].HostIP, strconv.Itoa(spec.Ports[0].HostPort)))
		if err != nil {
			return err
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				if !listening.Load() {
					c.Close() // the proxy: nothing behind it yet
					continue
				}
				go func() { // the service: waits for the client to speak
					defer c.Close()
					buf := make([]byte, 64)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}()
			}
		}()
		return nil
	}
	r := New(fe) // the real probes.Reachability
	c := load(t, "redis-unauthenticated-access")
	exp := Exposure{Mode: ModeHost, Bind: "127.0.0.1"}

	h, err := r.Run(context.Background(), c, "vulnerable", exp, Options{ReadyTimeout: 2 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	if h.Ready {
		t.Fatal("ready on the port proxy's accept, with nothing listening behind it")
	}
	if _, err := r.StopAll(context.Background(), c.ID()); err != nil {
		t.Fatal(err)
	}

	// The service comes up a second after start: ready then, not before.
	go func() {
		time.Sleep(time.Second)
		listening.Store(true)
	}()
	start := time.Now()
	h, err = r.Run(context.Background(), c, "vulnerable", exp, Options{ReadyTimeout: 20 * time.Second, Build: builder.Options{Pull: true}})
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	if !h.Ready {
		t.Fatalf("not ready once the service listens: %s", h.ReadyDetail)
	}
	if took < time.Second || took > 5*time.Second {
		t.Fatalf("ready after %s; want soon after the service listened (1s)", took)
	}
}
