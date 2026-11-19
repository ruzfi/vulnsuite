package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// A concurrent run can create the network between NetworkEnsure's inspect and
// its create; the 409 that follows must resolve to the existing network.
func TestNetworkEnsureConflictReinspects(t *testing.T) {
	var created atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			fmt.Fprint(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/networks/create"):
			created.Store(true) // the other run won the race
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"message":"network with name vulnsuite-net already exists"}`)
		case strings.HasSuffix(r.URL.Path, "/networks/vulnsuite-net"):
			if !created.Load() {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"message":"network vulnsuite-net not found"}`)
				return
			}
			fmt.Fprint(w, `{"Id":"net-other-run","Driver":"bridge","Internal":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"unexpected"}`)
		}
	}))
	defer srv.Close()
	c, err := New("tcp://" + strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.NetworkEnsure(context.Background(), engine.NetworkSpec{Name: "vulnsuite-net"})
	if err != nil || n.ID != "net-other-run" || !n.Internal {
		t.Fatalf("NetworkEnsure = %+v, %v; want the concurrently created network, as it is (internal)", n, err)
	}
}
