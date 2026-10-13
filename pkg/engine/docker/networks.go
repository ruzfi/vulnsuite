package docker

import (
	"context"
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

// NetworkEnsure creates the network when missing and returns its id.
func (c *Client) NetworkEnsure(ctx context.Context, spec engine.NetworkSpec) (string, error) {
	var existing struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/networks/"+url.PathEscape(spec.Name), nil, nil, &existing); err == nil {
		return existing.ID, nil
	} else if !IsNotFound(err) {
		return "", err
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
		"Labels":         map[string]string{"dev.vulnsuite.managed": "true"},
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
	var out struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/networks/create", nil, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// NetworkRemove deletes a network; missing is not an error.
func (c *Client) NetworkRemove(ctx context.Context, name string) error {
	err := c.doJSON(ctx, http.MethodDelete, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

var _ engine.Engine = (*Client)(nil)
