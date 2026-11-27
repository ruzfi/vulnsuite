package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// NetworkExists reports whether a network with this name exists.
func (c *Client) NetworkExists(ctx context.Context, name string) (bool, error) {
	err := c.doJSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if err == nil {
		return true, nil
	}
	if IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// networkJSON is the part of a network inspect vulnsuite reads.
type networkJSON struct {
	ID       string            `json:"Id"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	Options  map[string]string `json:"Options"`
	Labels   map[string]string `json:"Labels"`
	IPAM     struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
}

func (n networkJSON) network() engine.Network {
	out := engine.Network{ID: n.ID, Driver: n.Driver, Internal: n.Internal, Options: n.Options, Labels: n.Labels}
	if len(n.IPAM.Config) > 0 {
		out.Subnet, out.Gateway = n.IPAM.Config[0].Subnet, n.IPAM.Config[0].Gateway
	}
	return out
}

func (c *Client) networkInspect(ctx context.Context, name string) (engine.Network, error) {
	var n networkJSON
	if err := c.doJSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(name), nil, nil, &n); err != nil {
		return engine.Network{}, err
	}
	return n.network(), nil
}

// NetworkInspect returns the network; exists is false when it is missing.
func (c *Client) NetworkInspect(ctx context.Context, name string) (engine.Network, bool, error) {
	n, err := c.networkInspect(ctx, name)
	if err == nil {
		return n, true, nil
	}
	if IsNotFound(err) {
		return engine.Network{}, false, nil
	}
	return engine.Network{}, false, err
}

// networkLabels is spec's labels plus the managed label.
func networkLabels(spec engine.NetworkSpec) map[string]string {
	l := map[string]string{}
	for k, v := range spec.Labels {
		l[k] = v
	}
	l[engine.LabelManaged] = "true"
	return l
}

// NetworkEnsure creates the network when missing and returns it as the
// daemon reports it; an existing network is returned with its own settings.
func (c *Client) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (engine.Network, error) {
	if n, err := c.networkInspect(ctx, spec.Name); err == nil {
		return n, nil
	} else if !IsNotFound(err) {
		return engine.Network{}, err
	}
	driver := spec.Driver
	if driver == "" {
		driver = "bridge"
	}
	body := map[string]any{
		"Name":           spec.Name,
		"Driver":         driver,
		"CheckDuplicate": true,
		"Internal":       spec.Internal,
		"Labels":         networkLabels(spec),
	}
	if len(spec.Options) > 0 {
		body["Options"] = spec.Options
	}
	if spec.Subnet != "" {
		cfg := map[string]string{"Subnet": spec.Subnet}
		if spec.Gateway != "" {
			cfg["Gateway"] = spec.Gateway
		}
		body["IPAM"] = map[string]any{"Driver": "default", "Config": []map[string]string{cfg}}
	}
	if err := c.doJSON(ctx, http.MethodPost, "/networks/create", nil, body, nil); err != nil {
		// A concurrent run created it between our inspect and create: use
		// that one (the caller checks its settings).
		if IsConflict(err) {
			if n, ierr := c.networkInspect(ctx, spec.Name); ierr == nil {
				return n, nil
			}
		}
		return engine.Network{}, err
	}
	// Read back what the daemon made, so the caller sees the same fields for
	// a new network as for an existing one.
	n, err := c.networkInspect(ctx, spec.Name)
	if err != nil {
		return engine.Network{}, fmt.Errorf("inspect new network %s: %w", spec.Name, err)
	}
	return n, nil
}

// NetworkRemove deletes a network; missing is not an error.
func (c *Client) NetworkRemove(ctx context.Context, name string) error {
	err := c.doJSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// NetworkConnect attaches a container to a further network under aliases.
func (c *Client) NetworkConnect(ctx context.Context, network, container string, aliases []string) error {
	body := map[string]any{"Container": container}
	if len(aliases) > 0 {
		body["EndpointConfig"] = map[string]any{"Aliases": aliases}
	}
	return c.doJSON(ctx, http.MethodPost, "/networks/"+url.PathEscape(network)+"/connect", nil, body, nil)
}

var _ engine.Engine = (*Client)(nil)
