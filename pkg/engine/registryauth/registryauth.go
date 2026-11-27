// Package registryauth resolves registry credentials the way the docker CLI
// does: VULNSUITE_REGISTRY_USER/TOKEN, then credential helpers, then the
// plain auths in ~/.docker/config.json.
//
// The VULNSUITE_REGISTRY_USER/TOKEN pair names no registry, so it is scoped
// explicitly: templates choose which images are pulled, and a credential meant
// for the user's push registry must never be sent to a registry a template
// names. The pair is used only
//
//   - for the registry named by VULNSUITE_REGISTRY, when that is set (pulls and
//     pushes), or
//   - when VULNSUITE_REGISTRY is unset, for pushes only (the destination the
//     user chose with -registry), never for pulls.
//
// Credentials from ~/.docker/config.json and credential helpers are keyed by
// registry already and are used as before. Their keys are compared the way the
// docker CLI does (scheme and path ignored, so "https://reg.example.com/v2/"
// is reg.example.com). A credential helper runs at most once per server per
// process (its answer is cached) and is killed after helperTimeout, or when the
// caller's context ends.
package registryauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"
)

// Config is one registry credential.
type Config struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

type dockerConfig struct {
	Auths       map[string]authEntry `json:"auths"`
	CredsStore  string               `json:"credsStore"`
	CredHelpers map[string]string    `json:"credHelpers"`

	// helpers caches credential helper answers for this config, keyed by
	// helper and server.
	helpersMu sync.Mutex
	helpers   map[[2]string]*helperResult
}

// helperResult is one credential helper answer; done is closed once it is
// known. A result is shared only when cached is set: an answer cut short by
// its caller's context is not.
type helperResult struct {
	done   chan struct{}
	cfg    Config
	ok     bool
	cached bool
}

// helperTimeout bounds one credential helper run, so a helper that hangs (a
// keychain waiting for an unlock prompt, say) cannot block a build forever.
var helperTimeout = 10 * time.Second

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

// hubAddress is the key the docker CLI files Docker Hub credentials under.
const hubAddress = "https://index.docker.io/v1/"

// registryOf returns the credential key of an image reference's registry:
// hubAddress for Docker Hub ("nginx", "nginx:1.25", "postgres@sha256:...",
// "docker.io/library/nginx", ...) and host[:port] otherwise ("ghcr.io/x" ->
// "ghcr.io", "localhost:5000/x" -> "localhost:5000"). Tags and digests are
// ignored, so callers may pass the full reference.
func registryOf(ref string) string {
	var domain string
	if named, err := reference.ParseNormalizedNamed(ref); err == nil {
		domain = reference.Domain(named)
	} else {
		// Not a valid reference (e.g. upper case): apply the same rule by hand.
		first, rest, ok := strings.Cut(ref, "/")
		if ok && rest != "" && (strings.ContainsAny(first, ".:") || first == "localhost" || strings.HasPrefix(first, "[")) {
			domain = first
		}
	}
	switch domain {
	case "", "docker.io", "index.docker.io", "registry-1.docker.io":
		return hubAddress
	}
	return domain
}

// normalizeKey maps a docker config key (an auths or credHelpers entry) to the
// form registryOf returns, like the docker CLI's ConvertToHostname: the scheme
// and everything after the first "/" are dropped ("https://reg.example.com/v2/"
// -> "reg.example.com"), and every Docker Hub spelling ("docker.io",
// "index.docker.io", "https://index.docker.io/v1/", ...) is hubAddress.
func normalizeKey(key string) string {
	h := strings.TrimSpace(key)
	if _, rest, ok := strings.Cut(h, "://"); ok {
		h = rest
	}
	h, _, _ = strings.Cut(h, "/")
	switch strings.ToLower(h) {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		return hubAddress
	}
	return h
}

// sameRegistry reports whether config key matches reg, a key returned by
// registryOf.
func sameRegistry(key, reg string) bool {
	return strings.EqualFold(normalizeKey(key), reg)
}

// helperFor returns the credential helper for config key or registry reg: its
// credHelpers entry (matched like an auths key), else credsStore.
func (c *dockerConfig) helperFor(key string) string {
	if h, ok := c.CredHelpers[key]; ok {
		return h
	}
	reg := normalizeKey(key)
	for _, k := range sortedKeys(c.CredHelpers) {
		if sameRegistry(k, reg) {
			return c.CredHelpers[k]
		}
	}
	return c.CredsStore
}

// scopeRegistry is the credential key (as registryOf returns it) of the
// registry VULNSUITE_REGISTRY names, or "" when it is unset. It accepts a bare
// host ("ghcr.io", "localhost:5000", "docker.io"), a repository prefix as
// given to -registry ("ghcr.io/you/vulnsuite", "docker.io/you") or a URL
// ("https://index.docker.io/v1/"), so every Docker Hub spelling maps to the
// same key as a bare Hub reference such as "nginx:1.25".
func scopeRegistry() string {
	v := strings.TrimSpace(os.Getenv("VULNSUITE_REGISTRY"))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	v = strings.Trim(v, "/")
	if v == "" {
		return ""
	}
	host, _, _ := strings.Cut(v, "/")
	// Give registryOf a repository under the host, so a bare host is read
	// as a registry rather than as a Docker Hub image name.
	return registryOf(strings.ToLower(host) + "/x")
}

// envAllowed reports whether VULNSUITE_REGISTRY_USER/TOKEN may be sent to reg,
// a key returned by registryOf.
func envAllowed(reg string, push bool) bool {
	if scope := scopeRegistry(); scope != "" {
		return strings.EqualFold(reg, scope)
	}
	return push
}

// For returns the base64 X-Registry-Auth value for pulling an image ref, or ""
// when no credentials are known.
func For(ref string) string { return ForContext(context.Background(), ref) }

// ForContext is For with a context that bounds any credential helper run.
func ForContext(ctx context.Context, ref string) string {
	a, ok := lookup(ctx, ref, false)
	if !ok {
		return ""
	}
	return Encode(a)
}

// ForPush is For for pushing ref to the registry the user chose to publish to.
func ForPush(ref string) string { return ForPushContext(context.Background(), ref) }

// ForPushContext is ForPush with a context that bounds any credential helper run.
func ForPushContext(ctx context.Context, ref string) string {
	a, ok := lookup(ctx, ref, true)
	if !ok {
		return ""
	}
	return Encode(a)
}

// Lookup resolves the credential for pulling an image ref. The
// VULNSUITE_REGISTRY_USER/TOKEN pair is used only when VULNSUITE_REGISTRY
// names ref's registry.
func Lookup(ref string) (Config, bool) { return lookup(context.Background(), ref, false) }

// LookupPush resolves the credential for pushing ref.
func LookupPush(ref string) (Config, bool) { return lookup(context.Background(), ref, true) }

func lookup(ctx context.Context, ref string, push bool) (Config, bool) {
	reg := registryOf(ref)
	if u, t := os.Getenv("VULNSUITE_REGISTRY_USER"), os.Getenv("VULNSUITE_REGISTRY_TOKEN"); u != "" && t != "" && envAllowed(reg, push) {
		return Config{Username: u, Password: t, ServerAddress: reg}, true
	}
	conf := loadConfig()
	if conf == nil {
		return Config{}, false
	}
	if helper := conf.helperFor(reg); helper != "" {
		if a, ok := conf.fromHelper(ctx, helper, reg); ok {
			a.ServerAddress = reg
			return a, true
		}
	}
	for _, key := range sortedKeys(conf.Auths) {
		if !sameRegistry(key, reg) {
			continue
		}
		if a, ok := conf.Auths[key].config(reg); ok {
			return a, true
		}
	}
	return Config{}, false
}

// authEntry is one entry of a docker config's auths, in any of the forms the
// docker CLI writes and reads: a base64 "user:password" auth, separate
// username and password fields, and an identity (OAuth refresh) token, which
// e.g. az acr login stores beside a placeholder auth.
type authEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// config resolves e the way the docker CLI does: auth, when set, supplies the
// username and password, otherwise the separate fields do; an identity token
// is carried alongside. ok is false for an entry that holds no credential or
// whose auth is not base64 "user:password".
func (e authEntry) config(server string) (Config, bool) {
	u, p := e.Username, e.Password
	if e.Auth != "" {
		var ok bool
		if u, p, ok = plainAuth(e.Auth); !ok {
			return Config{}, false
		}
	}
	if u == "" && p == "" && e.IdentityToken == "" {
		return Config{}, false
	}
	return Config{Username: u, Password: p, IdentityToken: e.IdentityToken, ServerAddress: server}, true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// plainAuth decodes an auths entry's base64 "user:password".
func plainAuth(auth string) (user, pass string, ok bool) {
	if auth == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", false
	}
	return strings.Cut(string(raw), ":")
}

// fromHelper asks credential helper for server's credential. Each (helper,
// server) runs once per config: concurrent callers wait for the first run and
// later ones reuse its answer, unless that run was cut short by its caller's
// context, in which case the next caller runs the helper again.
func (c *dockerConfig) fromHelper(ctx context.Context, helper, server string) (Config, bool) {
	key := [2]string{helper, server}
	for {
		c.helpersMu.Lock()
		r := c.helpers[key]
		if r == nil {
			r = &helperResult{done: make(chan struct{})}
			if c.helpers == nil {
				c.helpers = map[[2]string]*helperResult{}
			}
			c.helpers[key] = r
			c.helpersMu.Unlock()
			r.cfg, r.ok = runHelper(ctx, helper, server)
			r.cached = ctx.Err() == nil
			if !r.cached {
				c.helpersMu.Lock()
				delete(c.helpers, key)
				c.helpersMu.Unlock()
			}
			close(r.done)
			return r.cfg, r.ok
		}
		c.helpersMu.Unlock()
		select {
		case <-r.done:
			if r.cached {
				return r.cfg, r.ok
			}
			if ctx.Err() != nil {
				return Config{}, false
			}
		case <-ctx.Done():
			return Config{}, false
		}
	}
}

// Warnings receives a line when a credential helper fails (missing, timed
// out, exited non-zero, unreadable output), so a pull that then fails as
// "unauthorized" is explained. Only the helper, the server and the failure
// are printed, never the helper's output (it may hold a secret). nil
// silences it.
var Warnings io.Writer = os.Stderr

// warned dedupes helper warnings: one per helper and server per process.
var warned sync.Map

func warnHelper(helper, server, format string, args ...any) {
	if Warnings == nil {
		return
	}
	if _, dup := warned.LoadOrStore(helper+"\x00"+server, true); dup {
		return
	}
	fmt.Fprintf(Warnings, "warning: credential helper docker-credential-%s for %s %s; continuing without its credentials\n",
		helper, server, fmt.Sprintf(format, args...))
}

// helperNotFound reports whether a helper's output is the docker credential
// protocol's "no credentials for this server" answer, which is no failure.
func helperNotFound(out []byte) bool {
	return bytes.Contains(bytes.ToLower(out), []byte("credentials not found"))
}

// runHelper runs docker-credential-<helper> get for server, bounded by ctx and
// helperTimeout.
func runHelper(ctx context.Context, helper, server string) (Config, bool) {
	bin := "docker-credential-" + helper
	if _, err := exec.LookPath(bin); err != nil {
		warnHelper(helper, server, "is not installed (%s not found in PATH)", bin)
		return Config{}, false
	}
	hctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(hctx, bin, "get")
	cmd.Stdin = strings.NewReader(server)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	// Do not wait on output pipes held open by the helper's own children
	// once it has been killed.
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		switch {
		case ctx.Err() != nil:
			// The caller gave up (Ctrl-C): not the helper's failure.
		case errors.Is(hctx.Err(), context.DeadlineExceeded):
			warnHelper(helper, server, "did not answer within %s (a locked keychain waiting for a prompt?)", helperTimeout)
		case helperNotFound(out.Bytes()) || helperNotFound(errOut.Bytes()):
		default:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				warnHelper(helper, server, "failed (exit status %d)", ee.ExitCode())
			} else {
				warnHelper(helper, server, "could not run: %v", err)
			}
		}
		return Config{}, false
	}
	var r struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		warnHelper(helper, server, "returned output that is not a credential")
		return Config{}, false
	}
	if r.Secret == "" {
		return Config{}, false
	}
	a := Config{Username: r.Username, Password: r.Secret, ServerAddress: server}
	if r.Username == "<token>" {
		a = Config{IdentityToken: r.Secret, ServerAddress: server}
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

// Configs returns every credential the docker config knows about, keyed by
// registry, for builds that pull from private registries. Each registry named
// in auths or credHelpers is resolved through its credential helper (the
// per-registry credHelpers entry, else credsStore) and falls back to the
// credential stored in auths (auth, username/password, identitytoken). Keys are normalised the way registryOf names a
// registry (hubAddress for Docker Hub, host[:port] otherwise); when several
// config keys name one registry, the first that resolves (in sorted order)
// wins.
func Configs() map[string]Config { return ConfigsContext(context.Background()) }

// ConfigsContext is Configs with a context that bounds credential helper runs.
func ConfigsContext(ctx context.Context) map[string]Config {
	conf := loadConfig()
	m := map[string]Config{}
	if conf == nil {
		return m
	}
	seen := map[string]bool{}
	var keys []string
	for _, k := range append(sortedKeys(conf.Auths), sortedKeys(conf.CredHelpers)...) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		reg := normalizeKey(key)
		if reg == "" {
			continue
		}
		if _, done := m[reg]; done {
			continue
		}
		// Ask the helper for the registry as docker login stores it (and
		// as lookup asks), so both share one cached answer.
		if helper := conf.helperFor(key); helper != "" {
			if a, ok := conf.fromHelper(ctx, helper, reg); ok {
				a.ServerAddress = reg
				m[reg] = a
				continue
			}
		}
		if a, ok := conf.Auths[key].config(reg); ok {
			m[reg] = a
		}
	}
	return m
}

// ConfigsHeader renders Configs as the X-Registry-Config header value ("" when empty).
func ConfigsHeader() string { return ConfigsHeaderContext(context.Background()) }

// ConfigsHeaderContext is ConfigsHeader with a context that bounds credential
// helper runs.
func ConfigsHeaderContext(ctx context.Context) string {
	m := ConfigsContext(ctx)
	if len(m) == 0 {
		return ""
	}
	b, _ := json.Marshal(m)
	return base64.URLEncoding.EncodeToString(b)
}
