package docker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// authConfig is what the daemon expects in X-Registry-Auth.
type authConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

type dockerConfig struct {
	Auths       map[string]struct{ Auth string } `json:"auths"`
	CredsStore  string                           `json:"credsStore"`
	CredHelpers map[string]string                `json:"credHelpers"`
}

var (
	cfgOnce sync.Once
	cfg     *dockerConfig
)

func loadConfig() *dockerConfig {
	cfgOnce.Do(func() {
		dir := os.Getenv("DOCKER_CONFIG")
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}
			dir = filepath.Join(home, ".docker")
		}
		b, err := os.ReadFile(filepath.Join(dir, "config.json"))
		if err != nil {
			return
		}
		var c dockerConfig
		if json.Unmarshal(b, &c) == nil {
			cfg = &c
		}
	})
	return cfg
}

// registryOf extracts the registry host of an image reference
// ("ghcr.io/ruzfi/x" -> "ghcr.io", "nginx" -> "https://index.docker.io/v1/").
func registryOf(ref string) string {
	first, _, _ := strings.Cut(ref, "/")
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		return first
	}
	return "https://index.docker.io/v1/"
}

// registryAuth returns the base64 X-Registry-Auth value for an image ref, or
// "" when no credentials are known. Credentials come from, in order:
// VULNSUITE_REGISTRY_USER/VULNSUITE_REGISTRY_TOKEN, a credential helper, or
// the plain auths in ~/.docker/config.json.
func (c *Client) registryAuth(ref string) string {
	reg := registryOf(ref)
	if u, t := os.Getenv("VULNSUITE_REGISTRY_USER"), os.Getenv("VULNSUITE_REGISTRY_TOKEN"); u != "" && t != "" {
		return encodeAuth(authConfig{Username: u, Password: t, ServerAddress: reg})
	}
	conf := loadConfig()
	if conf == nil {
		return ""
	}
	helper := conf.CredsStore
	if h, ok := conf.CredHelpers[reg]; ok {
		helper = h
	}
	if helper != "" {
		if a, ok := fromHelper(helper, reg); ok {
			return encodeAuth(a)
		}
	}
	for key, entry := range conf.Auths {
		if key == reg || strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://"), "/") == reg {
			if entry.Auth == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				continue
			}
			u, p, ok := strings.Cut(string(raw), ":")
			if !ok {
				continue
			}
			return encodeAuth(authConfig{Username: u, Password: p, ServerAddress: reg})
		}
	}
	return ""
}

func fromHelper(helper, reg string) (authConfig, bool) {
	bin := "docker-credential-" + helper
	if _, err := exec.LookPath(bin); err != nil {
		return authConfig{}, false
	}
	cmd := exec.Command(bin, "get")
	cmd.Stdin = strings.NewReader(reg)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return authConfig{}, false
	}
	var r struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Secret == "" {
		return authConfig{}, false
	}
	a := authConfig{Username: r.Username, Password: r.Secret, ServerAddress: reg}
	if r.Username == "<token>" {
		a = authConfig{IdentityToken: r.Secret, ServerAddress: reg}
	}
	return a, true
}

func encodeAuth(a authConfig) string {
	b, _ := json.Marshal(a)
	return base64.URLEncoding.EncodeToString(b)
}

func emptyAuth() string { return encodeAuth(authConfig{}) }

// registryConfigHeader builds X-Registry-Config for builds that pull from
// private registries (only plain auths; helpers are resolved lazily per pull).
func (c *Client) registryConfigHeader() string {
	conf := loadConfig()
	if conf == nil || len(conf.Auths) == 0 {
		return ""
	}
	m := map[string]authConfig{}
	for key, entry := range conf.Auths {
		raw, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			continue
		}
		u, p, ok := strings.Cut(string(raw), ":")
		if ok {
			m[key] = authConfig{Username: u, Password: p, ServerAddress: key}
		}
	}
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return base64.URLEncoding.EncodeToString(b)
}
