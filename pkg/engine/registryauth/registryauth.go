// Package registryauth resolves registry credentials the way the docker CLI
// does: VULNSUITE_REGISTRY_USER/TOKEN, then credential helpers, then the
// plain auths in ~/.docker/config.json.
package registryauth

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

// Config is one registry credential.
type Config struct {
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

// For returns the base64 X-Registry-Auth value for an image ref, or "" when
// no credentials are known.
func For(ref string) string {
	a, ok := Lookup(ref)
	if !ok {
		return ""
	}
	return Encode(a)
}

// Lookup resolves the credential for an image ref.
func Lookup(ref string) (Config, bool) {
	reg := registryOf(ref)
	if u, t := os.Getenv("VULNSUITE_REGISTRY_USER"), os.Getenv("VULNSUITE_REGISTRY_TOKEN"); u != "" && t != "" {
		return Config{Username: u, Password: t, ServerAddress: reg}, true
	}
	conf := loadConfig()
	if conf == nil {
		return Config{}, false
	}
	helper := conf.CredsStore
	if h, ok := conf.CredHelpers[reg]; ok {
		helper = h
	}
	if helper != "" {
		if a, ok := fromHelper(helper, reg); ok {
			return a, true
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
			return Config{Username: u, Password: p, ServerAddress: reg}, true
		}
	}
	return Config{}, false
}

func fromHelper(helper, reg string) (Config, bool) {
	bin := "docker-credential-" + helper
	if _, err := exec.LookPath(bin); err != nil {
		return Config{}, false
	}
	cmd := exec.Command(bin, "get")
	cmd.Stdin = strings.NewReader(reg)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return Config{}, false
	}
	var r struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Secret == "" {
		return Config{}, false
	}
	a := Config{Username: r.Username, Password: r.Secret, ServerAddress: reg}
	if r.Username == "<token>" {
		a = Config{IdentityToken: r.Secret, ServerAddress: reg}
	}
	return a, true
}

// Encode renders a credential as the daemon's base64 JSON header value.
func Encode(a Config) string {
	b, _ := json.Marshal(a)
	return base64.URLEncoding.EncodeToString(b)
}

// Empty is the header value for "no credentials".
func Empty() string { return Encode(Config{}) }

// Configs returns every plain credential in the docker config, keyed by
// registry, for builds that pull from private registries.
func Configs() map[string]Config {
	conf := loadConfig()
	m := map[string]Config{}
	if conf == nil {
		return m
	}
	for key, entry := range conf.Auths {
		raw, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			continue
		}
		u, p, ok := strings.Cut(string(raw), ":")
		if ok {
			m[key] = Config{Username: u, Password: p, ServerAddress: key}
		}
	}
	return m
}

// ConfigsHeader renders Configs as the X-Registry-Config header value ("" when empty).
func ConfigsHeader() string {
	m := Configs()
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return base64.URLEncoding.EncodeToString(b)
}
