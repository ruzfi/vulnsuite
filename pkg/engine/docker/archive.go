package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// ContainerPause freezes a running container (POST /containers/{id}/pause).
func (c *Client) ContainerPause(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/pause", nil, nil, nil)
}

// ContainerUnpause thaws a paused container (POST /containers/{id}/unpause).
func (c *Client) ContainerUnpause(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/unpause", nil, nil, nil)
}

// pathStatHeader carries the archive API's stat of the requested path: base64
// JSON with the mode as Go os.FileMode bits.
const pathStatHeader = "X-Docker-Container-Path-Stat"

type pathStat struct {
	Name string      `json:"name"`
	Size int64       `json:"size"`
	Mode fs.FileMode `json:"mode"`
}

func decodePathStat(h http.Header) (pathStat, error) {
	var st pathStat
	raw, err := base64.StdEncoding.DecodeString(h.Get(pathStatHeader))
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	if err != nil {
		return st, fmt.Errorf("decoding the daemon's %s header: %w", pathStatHeader, err)
	}
	return st, nil
}

// archive sends method (HEAD or GET) to /containers/{id}/archive for p and
// returns the response with its decoded path stat. A 404 is resolved into a
// missing container (the daemon's error) or a missing path (fs.ErrNotExist):
// a HEAD answer has no body to tell them apart.
func (c *Client) archive(ctx context.Context, method, id, p string) (*http.Response, pathStat, error) {
	if !path.IsAbs(p) {
		return nil, pathStat{}, fmt.Errorf("container path %q is not absolute", p)
	}
	// Cleaned, so a trailing "/" or "/." cannot make the daemon follow a
	// final symlink or change how it names the archive's entries.
	p = path.Clean(p)
	resp, err := c.do(ctx, method, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {p}}, nil, nil)
	if IsNotFound(err) {
		if _, ierr := c.ContainerInspect(ctx, id); ierr != nil {
			return nil, pathStat{}, ierr
		}
		return nil, pathStat{}, fmt.Errorf("%s in container %s: %w", p, id, fs.ErrNotExist)
	}
	if err != nil {
		return nil, pathStat{}, err
	}
	st, err := decodePathStat(resp.Header)
	if err != nil {
		resp.Body.Close()
		return nil, pathStat{}, err
	}
	return resp, st, nil
}

// ContainerStatPath returns the mode of p in the container (HEAD
// /containers/{id}/archive).
func (c *Client) ContainerStatPath(ctx context.Context, id, p string) (fs.FileMode, error) {
	resp, st, err := c.archive(ctx, http.MethodHead, id, p)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return st.Mode, nil
}

// ContainerReadDir returns the regular files directly in dir (GET
// /containers/{id}/archive), each cut to maxBytes.
func (c *Client) ContainerReadDir(ctx context.Context, id, dir string, maxBytes int64) (map[string]engine.FileContent, error) {
	resp, st, err := c.archive(ctx, http.MethodGet, id, dir)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !st.Mode.IsDir() {
		return nil, fmt.Errorf("%s in container %s is not a directory (mode %s)", dir, id, st.Mode)
	}
	return engine.DirFilesFromTar(resp.Body, st.Name, maxBytes)
}

var (
	_ engine.Pauser     = (*Client)(nil)
	_ engine.FileReader = (*Client)(nil)
)
