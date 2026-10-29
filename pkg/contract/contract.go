// Package contract defines the vulnerable-target contract: a portable,
// reproducible description of a vulnerable system and its patched
// counterpart.
//
// Design goals (a template describes how to stand up a vulnerable system and
// its patched twin; community-maintainable, one portable folder per target):
//
//   - One folder per target. The contract is a single YAML file plus any patch
//     and overlay files it references, all relative to the folder, so a
//     template is self-contained and runs on any device with Docker.
//   - Nix-inspired reproducibility: the base is pinned (an image digest, or an
//     upstream source at a pinned commit), and a state is reached from that
//     base by a patch and/or config overlay. Templates that share a base reuse
//     one built image, keyed by content.
//   - The scanner is NOT part of this. A target is something you build, stand
//     up and scan with your own probe.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// APIVersion is the contract version this build of vulnsuite speaks.
const APIVersion = "vulnsuite/v1"

// Kind is the only document kind.
const Kind = "Target"

// State names.
const (
	StateVulnerable = "vulnerable"
	StatePatched    = "patched"
)

// StateNames lists the states a contract may declare, in canonical order.
var StateNames = []string{StateVulnerable, StatePatched}

// Fidelity values.
const (
	FidelityReal      = "real"      // runs the genuine affected software
	FidelitySimulated = "simulated" // a stand-in that reproduces the behaviour
)

// Fidelities lists the allowed fidelity values.
var Fidelities = []string{FidelityReal, FidelitySimulated}

// ImageRepoPrefix is the local repository prefix for images vulnsuite builds.
const ImageRepoPrefix = "vulnsuite"

var durationRe = regexp.MustCompile(`^(\d+)([smh])$`)

// ParseDuration parses the contract's short duration form ("60s", "5m", "1h").
// An empty string returns def.
func ParseDuration(text string, def time.Duration) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return def, nil
	}
	m := durationRe.FindStringSubmatch(text)
	if m == nil {
		return 0, fmt.Errorf("bad duration %q (want e.g. 60s, 5m)", text)
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	switch m[2] {
	case "m":
		return time.Duration(n) * time.Minute, nil
	case "h":
		return time.Duration(n) * time.Hour, nil
	}
	return time.Duration(n) * time.Second, nil
}

// Port is a port the target listens on inside the container.
type Port struct {
	Container int    `yaml:"container" json:"container"`
	Protocol  string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	// Publish also publishes this port on the host (host mode) and includes it
	// in scanner target lists. The primary port is always published; this opts a
	// secondary port in. Ignored on the primary port, which is always published.
	Publish bool `yaml:"publish,omitempty" json:"publish,omitempty"`
}

// IsHTTP reports whether the port speaks HTTP(S).
func (p Port) IsHTTP() bool { return p.Protocol == "http" || p.Protocol == "https" }

// Scheme is the URL scheme a scanner should use for this port ("" for raw TCP).
func (p Port) Scheme() string {
	if p.IsHTTP() {
		return p.Protocol
	}
	return ""
}

// HTTPProbe is a raw HTTP request plus assertions on the response.
type HTTPProbe struct {
	Method        string            `yaml:"method,omitempty" json:"method,omitempty"`
	Port          int               `yaml:"port,omitempty" json:"port,omitempty"` // target a non-primary port (default: the primary port)
	Path          string            `yaml:"path,omitempty" json:"path,omitempty"`
	RawPath       string            `yaml:"raw_path,omitempty" json:"raw_path,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body          string            `yaml:"body,omitempty" json:"body,omitempty"`
	Status        *int              `yaml:"status,omitempty" json:"status,omitempty"`
	StatusIn      []int             `yaml:"status_in,omitempty" json:"status_in,omitempty"`
	BodyMatches   string            `yaml:"body_matches,omitempty" json:"body_matches,omitempty"`
	BodyAbsent    string            `yaml:"body_absent,omitempty" json:"body_absent,omitempty"`
	HeaderMatches map[string]string `yaml:"header_matches,omitempty" json:"header_matches,omitempty"`
	HeaderAbsent  []string          `yaml:"header_absent,omitempty" json:"header_absent,omitempty"`
	Timeout       float64           `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// Asserts reports whether the probe asserts anything at all.
func (h HTTPProbe) Asserts() bool {
	return h.Status != nil || len(h.StatusIn) > 0 || h.Strong()
}

// Strong reports whether the probe asserts on the body or a response header
// (a much stronger claim than a status code alone).
func (h HTTPProbe) Strong() bool {
	return h.BodyMatches != "" || h.BodyAbsent != "" || len(h.HeaderMatches) > 0 || len(h.HeaderAbsent) > 0
}

// ExecProbe runs a command inside the target container.
type ExecProbe struct {
	Run           string  `yaml:"run" json:"run"`
	ExpectExit    *int    `yaml:"expect_exit,omitempty" json:"expect_exit,omitempty"`
	StdoutMatches string  `yaml:"stdout_matches,omitempty" json:"stdout_matches,omitempty"`
	Timeout       float64 `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// TCPProbe opens a raw TCP connection, optionally sends bytes, and matches the banner.
type TCPProbe struct {
	Port          int     `yaml:"port" json:"port"`
	Send          string  `yaml:"send,omitempty" json:"send,omitempty"`
	BannerMatches string  `yaml:"banner_matches,omitempty" json:"banner_matches,omitempty"`
	Closed        bool    `yaml:"closed,omitempty" json:"closed,omitempty"` // assert the port is NOT open (connection refused/unreachable)
	Timeout       float64 `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// NetStep is one step of a scripted TCP dialogue: optionally send bytes, then
// read the response and assert on it. The first step usually only reads (a
// server banner).
type NetStep struct {
	Send         string `yaml:"send,omitempty" json:"send,omitempty"`
	Expect       string `yaml:"expect,omitempty" json:"expect,omitempty"`               // regex the response must match
	ExpectAbsent string `yaml:"expect_absent,omitempty" json:"expect_absent,omitempty"` // regex the response must NOT match
	Read         int    `yaml:"read,omitempty" json:"read,omitempty"`                   // bytes to read after this step (default 4096; 0 = skip read)
	NoRead       bool   `yaml:"no_read,omitempty" json:"no_read,omitempty"`             // send without reading a response
}

// NetProbe runs an ordered send/expect dialogue over one TCP connection, for
// multi-step protocols (FTP SITE commands, SMTP, line protocols) that a
// single-shot tcp probe cannot express.
type NetProbe struct {
	Port    int       `yaml:"port,omitempty" json:"port,omitempty"`
	TLS     bool      `yaml:"tls,omitempty" json:"tls,omitempty"`
	Steps   []NetStep `yaml:"steps" json:"steps"`
	Timeout float64   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// Probe proves a target is genuinely in its declared state. Exactly one of the
// kinds is set.
type Probe struct {
	HTTP *HTTPProbe `yaml:"http,omitempty" json:"http,omitempty"`
	Exec *ExecProbe `yaml:"exec,omitempty" json:"exec,omitempty"`
	TCP  *TCPProbe  `yaml:"tcp,omitempty" json:"tcp,omitempty"`
	Net  *NetProbe  `yaml:"net,omitempty" json:"net,omitempty"`
}

// Kind returns "http", "exec", "tcp" or "" when nothing is set.
func (p Probe) Kind() string {
	switch {
	case p.HTTP != nil:
		return "http"
	case p.Exec != nil:
		return "exec"
	case p.TCP != nil:
		return "tcp"
	case p.Net != nil:
		return "net"
	}
	return ""
}

// OverlayFile is a file from the template folder written into the image.
type OverlayFile struct {
	Src  string `yaml:"src" json:"src"`
	Dest string `yaml:"dest" json:"dest"`
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// SeedStep is a command run inside the container once it is up.
type SeedStep struct {
	Run string `yaml:"run" json:"run"`
}

// Base is the reusable, content-addressed foundation of a target.
type Base struct {
	Kind       string            `yaml:"kind" json:"kind"` // image | source | build
	Image      string            `yaml:"image,omitempty" json:"image,omitempty"`
	Digest     string            `yaml:"digest,omitempty" json:"digest,omitempty"`
	Repo       string            `yaml:"repo,omitempty" json:"repo,omitempty"`
	Commit     string            `yaml:"commit,omitempty" json:"commit,omitempty"`
	Dockerfile string            `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	Context    string            `yaml:"context,omitempty" json:"context,omitempty"`
	BuildArgs  map[string]string `yaml:"build_args,omitempty" json:"build_args,omitempty"`
}

// Base kinds.
const (
	BaseImage  = "image"
	BaseSource = "source"
	BaseBuild  = "build"
)

// Pinned reports whether the base is reproducible on another device.
func (b Base) Pinned() bool {
	switch b.Kind {
	case BaseImage:
		return b.Digest != ""
	case BaseSource:
		return b.Commit != ""
	}
	return true // a local build context is self-contained
}

// ImageRef is the fully pinned image reference of an image base.
func (b Base) ImageRef() string {
	if b.Kind != BaseImage || b.Image == "" {
		return ""
	}
	return pinRef(b.Image, b.Digest)
}

// ContentKey is the stable identity of the base, for image reuse.
func (b Base) ContentKey() string {
	df := b.Dockerfile
	if df == "" {
		df = "Dockerfile"
	}
	switch b.Kind {
	case BaseImage:
		return "image:" + b.ImageRef()
	case BaseSource:
		return fmt.Sprintf("source:%s@%s:%s", b.Repo, b.Commit, df)
	}
	return fmt.Sprintf("build:%s:%s", b.Context, df)
}

func pinRef(image, digest string) string {
	if digest == "" {
		return image
	}
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	return image + "@" + digest
}

// State describes how one state (vulnerable or patched) is reached from the base.
type State struct {
	Name        string                     `yaml:"-" json:"name"`
	Image       string                     `yaml:"image,omitempty" json:"image,omitempty"`
	Digest      string                     `yaml:"digest,omitempty" json:"digest,omitempty"`
	Patch       string                     `yaml:"patch,omitempty" json:"patch,omitempty"`
	Overlay     []OverlayFile              `yaml:"overlay,omitempty" json:"overlay,omitempty"`
	Environment map[string]string          `yaml:"environment,omitempty" json:"environment,omitempty"`
	Command     []string                   `yaml:"command,omitempty" json:"command,omitempty"`
	Sidecars    map[string]SidecarOverride `yaml:"sidecars,omitempty" json:"sidecars,omitempty"`
	Seed        []SeedStep                 `yaml:"seed,omitempty" json:"seed,omitempty"`
	Verify      []Probe                    `yaml:"verify,omitempty" json:"verify,omitempty"`
}

// SidecarRef is the image ref to run for sc in this state: a per-state override
// if present, otherwise the sidecar's own image.
func (s State) SidecarRef(sc Sidecar) string {
	if ov, ok := s.Sidecars[sc.Name]; ok && ov.Image != "" {
		return pinRef(ov.Image, ov.Digest)
	}
	return sc.Ref()
}

// EffectiveImage is the image ref for this state if it is image-based (a
// per-state override wins over the base). Empty for source/local builds.
func (s State) EffectiveImage(base Base) string {
	if s.Image != "" {
		return pinRef(s.Image, s.Digest)
	}
	if base.Kind == BaseImage {
		return base.ImageRef()
	}
	return ""
}

// Healthcheck tells the runner when the target is ready.
type Healthcheck struct {
	HTTP    *HTTPHealth `yaml:"http,omitempty" json:"http,omitempty"`
	TCP     *TCPHealth  `yaml:"tcp,omitempty" json:"tcp,omitempty"`
	Timeout string      `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// HTTPHealth is an HTTP readiness check.
type HTTPHealth struct {
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Status int    `yaml:"status,omitempty" json:"status,omitempty"`
}

// TCPHealth is a TCP readiness check.
type TCPHealth struct {
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
}

// Empty reports whether no healthcheck is declared.
func (h Healthcheck) Empty() bool { return h.HTTP == nil && h.TCP == nil && h.Timeout == "" }

// Sidecar is a helper container started next to the target.
type Sidecar struct {
	Name        string            `yaml:"name" json:"name"`
	Image       string            `yaml:"image" json:"image"`
	Digest      string            `yaml:"digest,omitempty" json:"digest,omitempty"`
	Command     []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
}

// Ref is the sidecar's pinned image reference.
func (s Sidecar) Ref() string { return pinRef(s.Image, s.Digest) }

// SidecarOverride lets a state swap a sidecar's image (e.g. the patched state
// of a multi-node target running the fixed version on every node).
type SidecarOverride struct {
	Image  string `yaml:"image" json:"image"`
	Digest string `yaml:"digest,omitempty" json:"digest,omitempty"`
}

// Service is how the target is run.
type Service struct {
	Ports       []Port            `yaml:"ports" json:"ports"`
	Command     []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Healthcheck Healthcheck       `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Sidecars    []Sidecar         `yaml:"sidecars,omitempty" json:"sidecars,omitempty"`
	User        string            `yaml:"user,omitempty" json:"user,omitempty"`
	CapAdd      []string          `yaml:"cap_add,omitempty" json:"cap_add,omitempty"`
	CapDrop     []string          `yaml:"cap_drop,omitempty" json:"cap_drop,omitempty"`
	Devices     []string          `yaml:"devices,omitempty" json:"devices,omitempty"`
}

// PrimaryPort is the port a scanner should be pointed at: the first HTTP port,
// else the first declared port.
func (s Service) PrimaryPort() Port {
	for _, p := range s.Ports {
		if p.IsHTTP() {
			return p
		}
	}
	if len(s.Ports) > 0 {
		return s.Ports[0]
	}
	return Port{}
}

// HostPublishPorts returns the ports made reachable to a scanner: the primary
// port (always, first), then every additional port marked publish: true, in
// declared order. Deduplicated by container port. This is the same set in every
// exposure mode -- published on the host in host mode, reached at the container
// (or macvlan) IP otherwise.
func (s Service) HostPublishPorts() []Port {
	primary := s.PrimaryPort()
	seen := map[int]bool{}
	var out []Port
	if primary.Container != 0 {
		out = append(out, primary)
		seen[primary.Container] = true
	}
	for _, p := range s.Ports {
		if p.Publish && !seen[p.Container] {
			out = append(out, p)
			seen[p.Container] = true
		}
	}
	return out
}

// Metadata identifies and documents the target.
type Metadata struct {
	ID         string   `yaml:"id" json:"id"`
	Summary    string   `yaml:"summary" json:"summary"`
	VulnRefs   []string `yaml:"vuln_refs,omitempty" json:"vuln_refs,omitempty"`
	CWE        []string `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	Severity   string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Tags       []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	References []string `yaml:"references,omitempty" json:"references,omitempty"`
	Maintainer string   `yaml:"maintainer,omitempty" json:"maintainer,omitempty"`
	Added      string   `yaml:"added,omitempty" json:"added,omitempty"`
	Updated    string   `yaml:"updated,omitempty" json:"updated,omitempty"`
	// Fidelity says whether the target runs the genuine affected software
	// (real) or a hand-written stand-in that reproduces its behaviour
	// (simulated). Real is the default and strongly preferred; simulated is
	// only honest when no public image or buildable upstream source
	// reproduces the flaw (bare-OS/device/protocol sims).
	Fidelity string `yaml:"fidelity,omitempty" json:"fidelity,omitempty"`
	// Detection says whether a stock scanner can find this target:
	//   scanner      the target reproduces a real scanner template's fingerprint
	//   custom-only  no public template exists; validate with your own probes
	Detection  string   `yaml:"detection,omitempty" json:"detection,omitempty"`
	DetectedBy []string `yaml:"detected_by,omitempty" json:"detected_by,omitempty"`
}

// Requires declares what the container host must provide for a target to run.
// The tooling preflights it against the detected host and skips, or runs under
// emulation, with a precise reason instead of hanging.
type Requires struct {
	// HostOS is the container-host OS(es) the target supports (default [linux]).
	HostOS []string `yaml:"host_os,omitempty" json:"host_os,omitempty"`
	// Arch is the host CPU arch(es) the target runs on natively (empty = any).
	Arch []string `yaml:"arch,omitempty" json:"arch,omitempty"`
	// Emulation permits running under qemu when the host arch is not in Arch
	// (default true). Set false for timing-sensitive or virt-backed targets.
	Emulation *bool `yaml:"emulation,omitempty" json:"emulation,omitempty"`
	// KVM marks a target that needs /dev/kvm + nested virtualization (e.g. a
	// Windows guest via dockur/windows); only a linux/amd64 host provides it.
	KVM bool `yaml:"kvm,omitempty" json:"kvm,omitempty"`
}

// EmulationAllowed reports whether qemu emulation is permitted (default true).
func (r Requires) EmulationAllowed() bool { return r.Emulation == nil || *r.Emulation }

// Empty reports whether no requirements are declared.
func (r Requires) Empty() bool {
	return len(r.HostOS) == 0 && len(r.Arch) == 0 && r.Emulation == nil && !r.KVM
}

// Contract is a fully loaded target template.
type Contract struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Metadata   Metadata          `yaml:"metadata" json:"metadata"`
	Base       Base              `yaml:"base" json:"base"`
	Service    Service           `yaml:"service" json:"service"`
	Requires   Requires          `yaml:"requires,omitempty" json:"requires,omitempty"`
	States     map[string]*State `yaml:"states" json:"states"`

	// Folder is the template directory; SourcePath the contract file. Both
	// absolute, both set by the loader.
	Folder     string `yaml:"-" json:"folder"`
	SourcePath string `yaml:"-" json:"source_path"`
}

// ID is a shortcut for Metadata.ID.
func (c *Contract) ID() string { return c.Metadata.ID }

// Updated returns the last-updated date, defaulting to Added when unset.
func (c *Contract) Updated() string {
	if c.Metadata.Updated == "" {
		return c.Metadata.Added
	}
	return c.Metadata.Updated
}

// Fidelity returns the declared fidelity, defaulting to real when unset.
func (c *Contract) Fidelity() string {
	if c.Metadata.Fidelity == "" {
		return FidelityReal
	}
	return c.Metadata.Fidelity
}

// IsSimulated reports whether the target is a stand-in rather than the real software.
func (c *Contract) IsSimulated() bool { return c.Fidelity() == FidelitySimulated }

// HasState reports whether the contract declares the named state.
func (c *Contract) HasState(name string) bool {
	st, ok := c.States[name]
	return ok && st != nil
}

// HasPatched reports whether a patched state exists.
func (c *Contract) HasPatched() bool { return c.HasState(StatePatched) }

// State returns the named state or an error.
func (c *Contract) State(name string) (*State, error) {
	st, ok := c.States[name]
	if !ok || st == nil {
		return nil, fmt.Errorf("template %s has no %q state", c.ID(), name)
	}
	return st, nil
}

// DeclaredStates returns the declared state names in canonical order.
func (c *Contract) DeclaredStates() []string {
	var out []string
	for _, n := range StateNames {
		if c.HasState(n) {
			out = append(out, n)
		}
	}
	return out
}

// Build kinds, cheapest first.
const (
	BuildKindImage   = "image"   // a prebuilt image, run as-is
	BuildKindOverlay = "overlay" // a prebuilt image with config files baked in
	BuildKindSource  = "source"  // cloned from a repo at a pinned commit (+ patch)
	BuildKindBuild   = "build"   // compiled from a Dockerfile in the template
)

// BuildKind reports how a state's image is produced.
func (c *Contract) BuildKind(stateName string) string {
	st, err := c.State(stateName)
	if err != nil {
		return ""
	}
	switch {
	case c.Base.Kind == BaseBuild:
		return BuildKindBuild
	case c.Base.Kind == BaseSource || st.Patch != "":
		return BuildKindSource
	case len(st.Overlay) > 0:
		return BuildKindOverlay
	}
	return BuildKindImage
}

// NeedsBuild reports whether the state produces a locally built image.
func (c *Contract) NeedsBuild(stateName string) bool {
	return c.BuildKind(stateName) != BuildKindImage
}

// ContentHash is the content-addressed tag of a built image of this state:
// identical inputs produce an identical tag, so a build is skipped and the
// existing image reused. Nix-inspired.
func (c *Contract) ContentHash(stateName string) string {
	st, err := c.State(stateName)
	if err != nil {
		return ""
	}
	// The state name is deliberately not part of the hash: the hash is the
	// identity of the *inputs*, so two states built from identical inputs are
	// recognised as identical (the validator warns about that).
	parts := []string{c.Base.ContentKey()}
	if c.Base.Kind == BaseBuild && c.Base.Context != "" {
		parts = append(parts, "context:"+hashTree(filepath.Join(c.Folder, c.Base.Context)))
	}
	if st.Patch != "" {
		parts = append(parts, fmt.Sprintf("patch:%s:%s", st.Patch, hashFile(filepath.Join(c.Folder, st.Patch))))
	}
	for _, o := range st.Overlay {
		parts = append(parts, fmt.Sprintf("overlay:%s:%s", o.Dest, hashFile(filepath.Join(c.Folder, o.Src))))
	}
	if len(st.Environment) > 0 {
		b, _ := json.Marshal(sortedMap(st.Environment))
		parts = append(parts, "env:"+string(b))
	}
	if len(c.Base.BuildArgs) > 0 {
		b, _ := json.Marshal(sortedMap(c.Base.BuildArgs))
		parts = append(parts, "args:"+string(b))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

// ImageTag is the local tag a built image of this state gets.
func (c *Contract) ImageTag(stateName string) string {
	return fmt.Sprintf("%s/%s:%s-%s", ImageRepoPrefix, c.ID(), stateName, c.ContentHash(stateName))
}

// ImageRef is the image a state runs: the built tag when a build happens,
// otherwise the (pinned) prebuilt image.
func (c *Contract) ImageRef(stateName string) string {
	if c.NeedsBuild(stateName) {
		return c.ImageTag(stateName)
	}
	st, _ := c.State(stateName)
	return st.EffectiveImage(c.Base)
}

// ContainerName is the deterministic name of a running target.
func (c *Contract) ContainerName(stateName string) string {
	return ContainerName(c.ID(), stateName)
}

// ContainerNamePrefix prefixes every container vulnsuite manages.
const ContainerNamePrefix = "vulnsuite-"

// ContainerName builds the container name for an id + state.
func ContainerName(id, stateName string) string {
	n := ContainerNamePrefix + strings.ReplaceAll(id, "/", "-") + "-" + stateName
	if len(n) > 120 {
		n = n[:120]
	}
	return n
}

// ParseContainerName splits a vulnsuite container name back into id + state.
func ParseContainerName(name string) (id, state string, ok bool) {
	if !strings.HasPrefix(name, ContainerNamePrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, ContainerNamePrefix)
	for _, s := range StateNames {
		if strings.HasSuffix(rest, "-"+s) {
			return strings.TrimSuffix(rest, "-"+s), s, true
		}
	}
	return "", "", false
}

func sortedMap(m map[string]string) map[string]string {
	// json.Marshal already sorts map keys; this exists to make intent explicit.
	return m
}

func hashFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// hashTree hashes a directory tree's relative paths and contents.
func hashTree(root string) string {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "missing"
	}
	var files []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	h := sha256.New()
	for _, p := range files {
		rel, _ := filepath.Rel(root, p)
		h.Write([]byte(filepath.ToSlash(rel)))
		b, err := os.ReadFile(p)
		if err == nil {
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
