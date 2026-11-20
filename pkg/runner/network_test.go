package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// -no-egress must not be dropped silently because vulnsuite-net already
// exists from an earlier run without it: the target would join a network with
// a route off the host. The run fails, says what differs and how to fix it,
// and starts nothing.
func TestNoEgressRefusesExistingEgressNetwork(t *testing.T) {
	fe, r := lifecycleRunner()
	mustRun(t, r, sidecarContract("foo"), "vulnerable", DefaultExposure())
	if fe.Networks[DefaultNetwork].Internal {
		t.Fatal("setup: the first run's network should have egress")
	}

	noEgress := DefaultExposure()
	noEgress.Internal = true
	_, err := r.Run(context.Background(), sidecarContract("bar"), "vulnerable", noEgress, pullOpts)
	if err == nil {
		t.Fatal("a -no-egress run joined the existing egress-capable vulnsuite-net")
	}
	for _, want := range []string{DefaultNetwork, "egress", "-no-egress", "vulnsuite stop -prune-net", "docker network rm vulnsuite-net"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if _, ok := fe.Containers[sidecarContract("bar").ContainerName("vulnerable")]; ok {
		t.Fatal("the target was created on the egress-capable network")
	}
	if fe.Networks[DefaultNetwork].Internal {
		t.Fatal("the existing network was changed")
	}

	// A custom network name is carried into the remedy.
	custom := noEgress
	custom.Network = "lab-net"
	if _, err := fe.NetworkEnsure(context.Background(), engine.NetworkSpec{Name: "lab-net"}); err != nil {
		t.Fatal(err)
	}
	_, err = r.Run(context.Background(), sidecarContract("bar"), "vulnerable", custom, pullOpts)
	if err == nil || !strings.Contains(err.Error(), "vulnsuite stop -network lab-net -prune-net") {
		t.Fatalf("want the remedy for lab-net, got %v", err)
	}
}

// The reverse mismatch is reported too: a run without -no-egress on an
// internal network would not get the egress it asked for.
func TestEgressRunRefusesExistingInternalNetwork(t *testing.T) {
	fe, r := lifecycleRunner()
	noEgress := DefaultExposure()
	noEgress.Internal = true
	mustRun(t, r, sidecarContract("foo"), "vulnerable", noEgress)
	_, err := r.Run(context.Background(), sidecarContract("bar"), "vulnerable", DefaultExposure(), pullOpts)
	if err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("want an error about the internal network, got %v", err)
	}
	// Matching flags keep working.
	mustRun(t, r, sidecarContract("baz"), "vulnerable", noEgress)
	if !fe.Networks[DefaultNetwork].Internal {
		t.Fatal("network changed")
	}
}

// The macvlan network is shared per parent interface: a later run asking for
// another -subnet or -gateway must not land on the old one.
func TestMacvlanRefusesExistingNetworkWithOtherSubnet(t *testing.T) {
	fe, r := lifecycleRunner()
	first := Exposure{Mode: ModeMacvlan, Parent: "eth0", Subnet: "192.168.1.0/24", Gateway: "192.168.1.1", IP: "192.168.1.50"}
	mustRun(t, r, sidecarContract("foo"), "vulnerable", first)

	// The same settings, written differently, are a match.
	same := first
	same.Subnet, same.IP = "192.168.1.7/24", "192.168.1.51"
	mustRun(t, r, sidecarContract("bar"), "vulnerable", same)

	other := Exposure{Mode: ModeMacvlan, Parent: "eth0", Subnet: "10.0.0.0/24", Gateway: "10.0.0.1", IP: "10.0.0.50"}
	_, err := r.Run(context.Background(), sidecarContract("baz"), "vulnerable", other, pullOpts)
	if err == nil {
		t.Fatal("a macvlan run with another subnet joined the existing network")
	}
	for _, want := range []string{"vulnsuite-macvlan-eth0", "192.168.1.0/24", "10.0.0.0/24", "192.168.1.1", "docker network rm vulnsuite-macvlan-eth0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if _, ok := fe.Containers[sidecarContract("baz").ContainerName("vulnerable")]; ok {
		t.Fatal("the target was created")
	}

	// Without -subnet/-gateway the existing network's addressing is fine.
	mustRun(t, r, sidecarContract("qux"), "vulnerable", Exposure{Mode: ModeMacvlan, Parent: "eth0", IP: "192.168.1.52"})
}

// A network vulnsuite did not create, with another driver, is not joined.
func TestNetworkWithOtherDriverIsRefused(t *testing.T) {
	fe, r := lifecycleRunner()
	fe.Networks[DefaultNetwork] = engine.NetworkSpec{Name: DefaultNetwork, Driver: "overlay"}
	_, err := r.Run(context.Background(), sidecarContract("foo"), "vulnerable", DefaultExposure(), pullOpts)
	if err == nil || !strings.Contains(err.Error(), `"overlay"`) {
		t.Fatalf("want a driver mismatch error, got %v", err)
	}
}
