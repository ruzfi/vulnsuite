// Package docker implements engine.Engine against the Docker Engine HTTP API,
// spoken directly over the daemon socket with the standard library. It works
// with Docker Engine, Docker Desktop, OrbStack, Colima and Podman's
// Docker-compatible socket, and honours DOCKER_HOST.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// APIVersion is the minimum Engine API version we need (Docker 20.10+).
const APIVersion = "v1.41"

// Client talks to one daemon.
type Client struct {
	http    *http.Client
	baseURL string // http://docker/v1.41 (host is a placeholder for unix sockets)
	host    string // what DOCKER_HOST resolved to, for messages
}

// Error is an API error with the daemon's message.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("docker api: %d: %s", e.Status, e.Message) }

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// DefaultHost is the socket used when DOCKER_HOST is unset.
func DefaultHost() string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}
	if runtime.GOOS == "windows" {
		return "npipe:////./pipe/docker_engine"
	}
	// Prefer the rootless / Desktop per-user socket when present.
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{
			filepath.Join(home, ".docker", "run", "docker.sock"),
			filepath.Join(home, ".orbstack", "run", "docker.sock"),
			filepath.Join(home, ".colima", "default", "docker.sock"),
		} {
			if _, err := os.Stat(p); err == nil {
				if _, err := os.Stat("/var/run/docker.sock"); err != nil {
					return "unix://" + p
				}
			}
		}
	}
	return "unix:///var/run/docker.sock"
}

// New connects to host (empty = DefaultHost()).
func New(host string) (*Client, error) {
	if host == "" {
		host = DefaultHost()
	}
	c := &Client{host: host}
	transport := &http.Transport{
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // builds and pulls can take a long time before the first byte
		Proxy:                 nil,
	}
	switch {
	case strings.HasPrefix(host, "unix://"):
		path := strings.TrimPrefix(host, "unix://")
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		c.baseURL = "http://docker/" + APIVersion
	case strings.HasPrefix(host, "tcp://"), strings.HasPrefix(host, "http://"):
		u, err := url.Parse(host)
		if err != nil {
			return nil, err
		}
		c.baseURL = "http://" + u.Host + "/" + APIVersion
	case strings.HasPrefix(host, "npipe://"):
		return nil, fmt.Errorf("npipe DOCKER_HOST is not supported yet; expose the daemon over tcp:// or use WSL")
	default:
		return nil, fmt.Errorf("unsupported DOCKER_HOST %q", host)
	}
	c.http = &http.Client{Transport: transport}
	return c, nil
}

// Host returns the daemon address in use.
func (c *Client) Host() string { return c.host }

func (c *Client) url(path string, q url.Values) string {
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// do performs a request and returns the response; non-2xx is turned into *Error.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path, q), body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, c.wrapDialError(err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		msg := strings.TrimSpace(string(b))
		var je struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &je) == nil && je.Message != "" {
			msg = je.Message
		}
		return nil, &Error{Status: resp.StatusCode, Message: msg}
	}
	return resp, nil
}

func (c *Client) wrapDialError(err error) error {
	var ne *net.OpError
	if errors.As(err, &ne) || strings.Contains(err.Error(), "connect:") {
		return fmt.Errorf("cannot reach the Docker daemon at %s (is Docker running? set DOCKER_HOST to point elsewhere): %w", c.host, err)
	}
	return err
}

// doJSON performs a request with an optional JSON body and decodes a JSON response into out.
func (c *Client) doJSON(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var body io.Reader
	headers := map[string]string{}
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
		headers["Content-Type"] = "application/json"
	}
	resp, err := c.do(ctx, method, path, q, body, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping returns the daemon version.
func (c *Client) Ping(ctx context.Context) (string, error) {
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		Os         string `json:"Os"`
		Arch       string `json:"Arch"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s (api %s, %s/%s)", v.Version, v.APIVersion, v.Os, v.Arch), nil
}

// Info returns the daemon OS/arch.
func (c *Client) Info(ctx context.Context) (engine.HostInfo, error) {
	var v struct {
		Os   string `json:"Os"`
		Arch string `json:"Arch"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		return engine.HostInfo{}, err
	}
	return engine.HostInfo{OS: v.Os, Arch: v.Arch}, nil
}

// streamMessage is one line of a JSON progress stream (build, pull, push).
type streamMessage struct {
	Stream      string `json:"stream"`
	Status      string `json:"status"`
	Progress    string `json:"progress"`
	ID          string `json:"id"`
	Error       string `json:"error"`
	ErrorDetail *struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
	Aux json.RawMessage `json:"aux"`
}

// drainStream consumes a JSON progress stream, writing human text to out and
// returning the first error the daemon reported.
func drainStream(r io.Reader, out io.Writer) error {
	dec := json.NewDecoder(r)
	var lastStatus string
	for {
		var m streamMessage
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading daemon stream: %w", err)
		}
		if m.Error != "" {
			msg := m.Error
			if m.ErrorDetail != nil && m.ErrorDetail.Message != "" {
				msg = m.ErrorDetail.Message
			}
			return errors.New(strings.TrimSpace(msg))
		}
		if out == nil {
			continue
		}
		switch {
		case m.Stream != "":
			io.WriteString(out, m.Stream)
		case m.Status != "":
			// pull/push progress: collapse per-layer noise to status changes
			line := m.Status
			if m.ID != "" {
				line = m.ID + ": " + line
			}
			if line != lastStatus && m.Progress == "" {
				io.WriteString(out, line+"\n")
				lastStatus = line
			}
		}
	}
}
