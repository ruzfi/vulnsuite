package contract

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Command accepts either a YAML string or a list of strings.
type Command []string

// UnmarshalYAML implements yaml.InterfaceUnmarshaler.
func (c *Command) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		*c = Command{s}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return errors.New("command must be a string or a list of strings")
	}
	*c = Command(list)
	return nil
}

// rawContract mirrors Contract for strict decoding (the Command shim and the
// YAML-only fields live here).
type rawContract struct {
	APIVersion string               `yaml:"apiVersion"`
	Kind       string               `yaml:"kind"`
	Metadata   Metadata             `yaml:"metadata"`
	Base       Base                 `yaml:"base"`
	Service    rawService           `yaml:"service"`
	Requires   Requires             `yaml:"requires"`
	States     map[string]*rawState `yaml:"states"`
}

type rawService struct {
	Ports       []Port            `yaml:"ports"`
	Command     Command           `yaml:"command,omitempty"`
	Environment map[string]string `yaml:"environment,omitempty"`
	Healthcheck Healthcheck       `yaml:"healthcheck,omitempty"`
	Sidecars    []Sidecar         `yaml:"sidecars,omitempty"`
	User        string            `yaml:"user,omitempty"`
	CapAdd      []string          `yaml:"cap_add,omitempty"`
	CapDrop     []string          `yaml:"cap_drop,omitempty"`
	Devices     []string          `yaml:"devices,omitempty"`
}

type rawState struct {
	Image       string                     `yaml:"image,omitempty"`
	Digest      string                     `yaml:"digest,omitempty"`
	Patch       string                     `yaml:"patch,omitempty"`
	Overlay     []OverlayFile              `yaml:"overlay,omitempty"`
	Environment map[string]string          `yaml:"environment,omitempty"`
	Command     Command                    `yaml:"command,omitempty"`
	Sidecars    map[string]SidecarOverride `yaml:"sidecars,omitempty"`
	Seed        []SeedStep                 `yaml:"seed,omitempty"`
	Verify      []Probe                    `yaml:"verify,omitempty"`
}

const (
	idMinLen = 3
	idMaxLen = 80
)

// SchemaError is a structural error in a contract document (the equivalent of
// a JSON-schema violation).
type SchemaError struct {
	Loc     string
	Message string
}

func (e *SchemaError) Error() string { return fmt.Sprintf("schema: %s: %s", e.Loc, e.Message) }

var (
	// idRe is a valid Docker repository path component (no leading, trailing
	// or doubled separators); idMinLen/idMaxLen bound it as the schema does.
	idRe = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)*$`)
	// vulnRefRe is a CVE id, a GHSA id, or a generic PREFIX-ID whose prefix
	// is 2-8 upper-case letters other than CVE and GHSA, so a malformed
	// CVE-21-41773 is rejected instead of passing as a generic ref (and then
	// not being treated as a CVE). The prefix alternatives spell out "not CVE,
	// not GHSA" without a lookahead, so the schema can use the same pattern.
	vulnRefRe = regexp.MustCompile(`^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9-]+|` +
		`([A-Z]{2}|[A-BD-Z][A-Z]{2}|C[A-UW-Z][A-Z]|CV[A-DF-Z]|[A-FH-Z][A-Z]{3}|G[A-GI-Z][A-Z]{2}|GH[A-RT-Z][A-Z]|GHS[B-Z]|[A-Z]{5,8})` +
		`-[A-Z0-9-]+)$`)
	// refShapeRe is vulnRefRe case-insensitively, for recognising a ref-shaped
	// selector or filter value (CVE-, GHSA-, GO-, VS-... in any case).
	refShapeRe = regexp.MustCompile(`(?i)^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9-]+|[A-Z]{2,8}-[A-Z0-9-]+)$`)
	cweRe      = regexp.MustCompile(`^CWE-\d+$`)
	// handleRe is the pattern for a group handle and a variant discriminator:
	// lower-case alphanumerics in dash-separated segments.
	handleRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	userRe     = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)
	capRe      = regexp.MustCompile(`^[A-Z_]+$`)
	deviceRe   = regexp.MustCompile(`^/dev/[a-zA-Z0-9/_-]+$`)
	modeRe     = regexp.MustCompile(`^0[0-7]{3}$`)
	timeoutRe  = regexp.MustCompile(`^\d+[smh]$`)
	cpuFlagRe  = regexp.MustCompile(`^[a-z0-9_]+$`)
	severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	protocols  = map[string]bool{"http": true, "https": true, "tcp": true, "ssh": true, "ftp": true,
		"smtp": true, "redis": true, "mysql": true, "postgres": true}
	detections = map[string]bool{"scanner": true, "custom-only": true}
	fidelities = map[string]bool{"real": true, "simulated": true}
	classes    = map[string]bool{"vuln": true, "misconfig": true, "exposure": true, "default-login": true, "weak-crypto": true}
	hostOSes   = map[string]bool{"linux": true, "windows": true}
	arches     = map[string]bool{"amd64": true, "arm64": true, "386": true, "arm": true, "ppc64le": true, "s390x": true, "riscv64": true}
)

// Parse decodes and structurally validates a contract document. Semantic lint
// (is the template *wrong* rather than malformed?) lives in package validator.
func Parse(data []byte) (*Contract, error) {
	// Aliases are checked before decoding: goccy expands them (and merge
	// keys) without a limit, so an alias bomb must be stopped first.
	file, perr := parser.ParseBytes(data, 0)
	var anchors map[string]ast.Node
	if perr == nil {
		var err error
		if anchors, err = checkAliases(file); err != nil {
			return nil, err
		}
	}
	var raw rawContract
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("invalid YAML: %s", strings.TrimSpace(yaml.FormatError(err, false, false)))
	}
	if perr != nil { // the decoder reports syntax errors itself; a backstop
		return nil, fmt.Errorf("invalid YAML: %w", perr)
	}
	if err := checkDocument(file, anchors); err != nil {
		return nil, err
	}
	c := &Contract{
		APIVersion: raw.APIVersion,
		Kind:       raw.Kind,
		Metadata:   raw.Metadata,
		Base:       raw.Base,
		Requires:   raw.Requires,
		Service: Service{
			Ports:       raw.Service.Ports,
			Command:     []string(raw.Service.Command),
			Environment: raw.Service.Environment,
			Healthcheck: raw.Service.Healthcheck,
			Sidecars:    raw.Service.Sidecars,
			User:        raw.Service.User,
			CapAdd:      raw.Service.CapAdd,
			CapDrop:     raw.Service.CapDrop,
			Devices:     raw.Service.Devices,
		},
		States: map[string]*State{},
	}
	for name, rs := range raw.States {
		if rs == nil {
			c.States[name] = nil
			continue
		}
		c.States[name] = &State{
			Name:        name,
			Image:       rs.Image,
			Digest:      rs.Digest,
			Patch:       rs.Patch,
			Overlay:     rs.Overlay,
			Environment: rs.Environment,
			Command:     []string(rs.Command),
			Sidecars:    rs.Sidecars,
			Seed:        rs.Seed,
			Verify:      rs.Verify,
		}
	}
	// Which base keys are present, even with an empty value: the schema
	// rejects `context: ""` on an image base like any other foreign key.
	var keys struct {
		Base map[string]any `yaml:"base"`
	}
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("invalid YAML: %s", strings.TrimSpace(yaml.FormatError(err, false, false)))
	}
	if err := c.checkStructure(keys.Base); err != nil {
		return nil, err
	}
	return c, nil
}

func se(loc, format string, args ...any) error {
	return &SchemaError{Loc: loc, Message: fmt.Sprintf(format, args...)}
}

// baseKeys are the keys each base kind allows, besides kind itself.
var baseKeys = map[string]map[string]bool{
	BaseImage:  {"image": true, "digest": true},
	BaseSource: {"repo": true, "commit": true, "dockerfile": true, "build_args": true},
	BaseBuild:  {"context": true, "dockerfile": true, "build_args": true},
}

// checkStructure enforces the same rules as schemas/contract.schema.json.
// present holds the keys written under base, empty values included.
func (c *Contract) checkStructure(present map[string]any) error {
	if c.APIVersion != APIVersion {
		return se("apiVersion", "must be %q (got %q)", APIVersion, c.APIVersion)
	}
	if c.Kind != Kind {
		return se("kind", "must be %q", Kind)
	}
	m := c.Metadata
	if !idRe.MatchString(m.ID) || len(m.ID) < idMinLen || len(m.ID) > idMaxLen {
		return se("metadata/id", "%q must match %s and be %d-%d characters", m.ID, idRe, idMinLen, idMaxLen)
	}
	if strings.TrimSpace(m.Summary) == "" {
		return se("metadata/summary", "is required")
	}
	for i, r := range m.VulnRefs {
		if !vulnRefRe.MatchString(r) {
			return se(fmt.Sprintf("metadata/vuln_refs/%d", i), "%q must be a CVE-, GHSA- or PREFIX-ID reference", r)
		}
	}
	for i, r := range m.CWE {
		if !cweRe.MatchString(r) {
			return se(fmt.Sprintf("metadata/cwe/%d", i), "%q must look like CWE-22", r)
		}
	}
	if m.Severity != "" && !severities[m.Severity] {
		return se("metadata/severity", "%q is not one of info, low, medium, high, critical", m.Severity)
	}
	if m.Detection != "" && !detections[m.Detection] {
		return se("metadata/detection", "%q is not one of scanner, custom-only", m.Detection)
	}
	if m.Fidelity != "" && !fidelities[m.Fidelity] {
		return se("metadata/fidelity", "%q is not one of real, simulated", m.Fidelity)
	}
	seenClass := map[string]bool{}
	for i, cl := range m.Class {
		if !classes[cl] {
			return se(fmt.Sprintf("metadata/class/%d", i), "%q is not one of vuln, misconfig, exposure, default-login, weak-crypto", cl)
		}
		if seenClass[cl] {
			return se(fmt.Sprintf("metadata/class/%d", i), "class %q is listed more than once", cl)
		}
		seenClass[cl] = true
	}
	if m.Disclosed != "" {
		if _, err := time.Parse(time.DateOnly, m.Disclosed); err != nil {
			return se("metadata/disclosed", "%q must be an ISO date (YYYY-MM-DD)", m.Disclosed)
		}
	}
	if m.Group != "" && !handleRe.MatchString(m.Group) {
		return se("metadata/group", "%q must match %s", m.Group, handleRe)
	}
	if m.Variant != "" && !handleRe.MatchString(m.Variant) {
		return se("metadata/variant", "%q must match %s", m.Variant, handleRe)
	}
	if m.Variant != "" && m.Group == "" {
		return se("metadata/variant", "a variant needs a group")
	}

	b := c.Base
	if allowed, ok := baseKeys[b.Kind]; ok {
		for _, k := range sortedKeys(present) {
			if k != "kind" && !allowed[k] {
				switch b.Kind {
				case BaseImage:
					return se("base", "kind: image allows only image and digest")
				case BaseSource:
					return se("base", "kind: source allows only repo, commit, dockerfile, build_args")
				default:
					return se("base", "kind: build allows only context, dockerfile, build_args")
				}
			}
		}
	}
	switch b.Kind {
	case BaseImage:
		if b.Image == "" {
			return se("base/image", "is required for kind: image")
		}
	case BaseSource:
		if b.Repo == "" || b.Commit == "" {
			return se("base", "kind: source requires repo and commit")
		}
	case BaseBuild:
		if b.Context == "" {
			return se("base/context", "is required for kind: build")
		}
		if err := checkLocalPath(b.Context); err != nil {
			return se("base/context", "%q %v", b.Context, err)
		}
	default:
		return se("base/kind", "%q is not one of image, source, build", b.Kind)
	}
	if b.Digest != "" && !digestRe.MatchString(b.Digest) {
		return se("base/digest", "must look like sha256:<64 hex>")
	}
	if b.Dockerfile != "" {
		if err := checkLocalPath(b.Dockerfile); err != nil {
			return se("base/dockerfile", "%q %v", b.Dockerfile, err)
		}
	}

	for i, o := range c.Requires.HostOS {
		if !hostOSes[o] {
			return se(fmt.Sprintf("requires/host_os/%d", i), "%q is not one of linux, windows", o)
		}
	}
	for i, a := range c.Requires.Arch {
		if !arches[a] {
			return se(fmt.Sprintf("requires/arch/%d", i), "%q is not a known GOARCH (amd64, arm64, ...)", a)
		}
	}
	seenFlag := map[string]bool{}
	for i, f := range c.Requires.CPUFlags {
		if !cpuFlagRe.MatchString(f) {
			return se(fmt.Sprintf("requires/cpu_flags/%d", i), "%q is not a /proc/cpuinfo flag name (lower-case letters, digits, _)", f)
		}
		if seenFlag[f] {
			return se(fmt.Sprintf("requires/cpu_flags/%d", i), "%q is listed more than once", f)
		}
		seenFlag[f] = true
	}
	if p := c.Requires.Probe; p != nil {
		if strings.TrimSpace(p.Run) == "" {
			return se("requires/probe/run", "must be a non-empty shell command")
		}
		if strings.TrimSpace(p.Reason) == "" {
			return se("requires/probe/reason", "must say what a host that fails the probe lacks")
		}
		if p.Timeout != "" && !timeoutRe.MatchString(p.Timeout) {
			return se("requires/probe/timeout", "must look like 30s or 2m")
		}
	}

	s := c.Service
	if len(s.Ports) == 0 {
		return se("service/ports", "at least one port is required")
	}
	seenPort := map[int]bool{}
	for i, p := range s.Ports {
		if p.Container < 1 || p.Container > 65535 {
			return se(fmt.Sprintf("service/ports/%d/container", i), "must be 1..65535")
		}
		if p.Protocol != "" && !protocols[p.Protocol] {
			return se(fmt.Sprintf("service/ports/%d/protocol", i), "%q is not a known protocol", p.Protocol)
		}
		if seenPort[p.Container] {
			return se(fmt.Sprintf("service/ports/%d/container", i), "port %d is declared more than once", p.Container)
		}
		seenPort[p.Container] = true
	}
	if s.User != "" && !userRe.MatchString(s.User) {
		return se("service/user", "must be uid or uid:gid")
	}
	for _, cp := range append(append([]string{}, s.CapAdd...), s.CapDrop...) {
		if !capRe.MatchString(cp) {
			return se("service/cap_add|cap_drop", "%q must be an upper-case capability name", cp)
		}
	}
	for _, d := range s.Devices {
		if !deviceRe.MatchString(d) {
			return se("service/devices", "%q must be a /dev path", d)
		}
		if !allowedDevice(d) {
			return se("service/devices", "%q is not an allowed device (allowed: /dev/kvm, /dev/net/tun, /dev/fuse, /dev/vhost-net, /dev/vhost-vsock, /dev/dri/cardN, /dev/dri/renderDN); raw disk/memory and other host devices are never needed for a target", d)
		}
	}
	if s.Healthcheck.Timeout != "" && !timeoutRe.MatchString(s.Healthcheck.Timeout) {
		return se("service/healthcheck/timeout", "must look like 60s or 5m")
	}
	seenSidecar := map[string]bool{}
	for i, sc := range s.Sidecars {
		if sc.Name == "" || sc.Image == "" {
			return se(fmt.Sprintf("service/sidecars/%d", i), "name and image are required")
		}
		if seenSidecar[sc.Name] {
			return se(fmt.Sprintf("service/sidecars/%d/name", i), "sidecar %q is declared more than once", sc.Name)
		}
		seenSidecar[sc.Name] = true
		if sc.Digest != "" && !digestRe.MatchString(sc.Digest) {
			return se(fmt.Sprintf("service/sidecars/%d/digest", i), "must look like sha256:<64 hex>")
		}
	}

	if len(c.States) == 0 || !c.HasState(StateVulnerable) {
		return se("states/vulnerable", "is required")
	}
	// Check names before contents, and states in a fixed order, so a contract
	// with several errors always reports the same one (ranging over the map
	// would pick one at random).
	names := make([]string, 0, len(c.States))
	for name := range c.States {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !has(StateNames, name) {
			return se("states/"+name, "unknown state; only vulnerable and patched are allowed")
		}
	}
	for _, name := range StateNames {
		st, ok := c.States[name]
		if !ok {
			continue
		}
		if st == nil {
			return se("states/"+name, "must be a mapping")
		}
		loc := "states/" + name
		if st.Digest != "" && !digestRe.MatchString(st.Digest) {
			return se(loc+"/digest", "must look like sha256:<64 hex>")
		}
		// A source or build base builds every state from the same checkout or
		// context; nothing runs FROM a state image there, so one would be
		// silently ignored and "patched" would still be the vulnerable build.
		if b.Kind != BaseImage {
			if st.Image != "" {
				return se(loc+"/image", "a per-state image applies only to kind: image; a %s base builds every state from its own source, so make the states differ with a patch or overlay", b.Kind)
			}
			if st.Digest != "" {
				return se(loc+"/digest", "pins a per-state image, which applies only to kind: image")
			}
		}
		if st.Patch != "" {
			if err := checkLocalPath(st.Patch); err != nil {
				return se(loc+"/patch", "%q %v", st.Patch, err)
			}
		}
		for i, o := range st.Overlay {
			if o.Src == "" || o.Dest == "" {
				return se(fmt.Sprintf("%s/overlay/%d", loc, i), "src and dest are required")
			}
			if err := checkLocalPath(o.Src); err != nil {
				return se(fmt.Sprintf("%s/overlay/%d/src", loc, i), "%q %v", o.Src, err)
			}
			if err := checkOverlayDest(o.Dest, b.Kind == BaseImage); err != nil {
				return se(fmt.Sprintf("%s/overlay/%d/dest", loc, i), "%q %v", o.Dest, err)
			}
			if o.Mode != "" && !modeRe.MatchString(o.Mode) {
				return se(fmt.Sprintf("%s/overlay/%d/mode", loc, i), "must be an octal mode like 0644")
			}
		}
		for _, k := range sortedKeys(st.Environment) {
			if err := CheckEnv(k, st.Environment[k]); err != nil {
				return se(loc+"/environment", "%v", err)
			}
		}
		scNames := make([]string, 0, len(st.Sidecars))
		for scName := range st.Sidecars {
			scNames = append(scNames, scName)
		}
		sort.Strings(scNames)
		for _, scName := range scNames {
			ov := st.Sidecars[scName]
			if ov.Image == "" {
				return se(fmt.Sprintf("%s/sidecars/%s/image", loc, scName), "is required")
			}
			if ov.Digest != "" && !digestRe.MatchString(ov.Digest) {
				return se(fmt.Sprintf("%s/sidecars/%s/digest", loc, scName), "must look like sha256:<64 hex>")
			}
			found := false
			for _, sc := range c.Service.Sidecars {
				if sc.Name == scName {
					found = true
					break
				}
			}
			if !found {
				return se(fmt.Sprintf("%s/sidecars/%s", loc, scName), "no service sidecar named %q to override", scName)
			}
		}
		for i, step := range st.Seed {
			if step.Run == "" {
				return se(fmt.Sprintf("%s/seed/%d/run", loc, i), "is required")
			}
		}
		for i, p := range st.Verify {
			ploc := fmt.Sprintf("%s/verify/%d", loc, i)
			n := 0
			if p.HTTP != nil {
				n++
				if err := checkProbeNums(ploc+"/http", p.HTTP.Port, p.HTTP.Timeout); err != nil {
					return err
				}
			}
			if p.Exec != nil {
				n++
				if p.Exec.Run == "" {
					return se(ploc+"/exec/run", "is required")
				}
				if err := checkProbeNums(ploc+"/exec", 0, p.Exec.Timeout); err != nil {
					return err
				}
			}
			if p.TCP != nil {
				n++
				if p.TCP.Port == 0 {
					return se(ploc+"/tcp/port", "is required")
				}
				if err := checkProbeNums(ploc+"/tcp", p.TCP.Port, p.TCP.Timeout); err != nil {
					return err
				}
			}
			if p.Net != nil {
				n++
				if len(p.Net.Steps) == 0 {
					return se(ploc+"/net/steps", "at least one step is required")
				}
				if err := checkProbeNums(ploc+"/net", p.Net.Port, p.Net.Timeout); err != nil {
					return err
				}
			}
			if n != 1 {
				return se(ploc, "exactly one of http, exec, tcp, net must be set")
			}
		}
	}
	return nil
}

// checkProbeNums enforces a probe's port range (0 = the default, primary port)
// and a non-negative timeout (0 = the default).
func checkProbeNums(loc string, port int, timeout float64) error {
	if port < 0 || port > 65535 {
		return se(loc+"/port", "must be 1..65535")
	}
	if timeout < 0 {
		return se(loc+"/timeout", "must be greater than 0")
	}
	return nil
}

// allowedDevices are the host devices a template may pass through (still
// consent-gated at run time by -allow-host-access). Everything else is
// rejected at parse time: a denylist of raw disk/memory devices cannot be made
// complete (LVM /dev/<vg>/<lv>, zvols, nbd, rbd, /dev/root, by-id links, …), and
// none of those is ever needed to stand up a vulnerable service.
var allowedDevices = []*regexp.Regexp{
	regexp.MustCompile(`^/dev/kvm$`),         // KVM/QEMU targets
	regexp.MustCompile(`^/dev/net/tun$`),     // VPN / tunnelling services
	regexp.MustCompile(`^/dev/fuse$`),        // FUSE file systems
	regexp.MustCompile(`^/dev/vhost-net$`),   // virtio networking for QEMU
	regexp.MustCompile(`^/dev/vhost-vsock$`), // virtio vsock for QEMU
	regexp.MustCompile(`^/dev/dri/(card|renderD)[0-9]+$`),
}

// allowedDevice reports whether d is an exact, canonical path on the device
// allowlist. Non-canonical spellings (/dev//kvm) are refused rather than
// cleaned: the daemon resolves them, so the string that is checked must be
// the string that is passed through.
func allowedDevice(d string) bool {
	if path.Clean(d) != d {
		return false
	}
	for _, re := range allowedDevices {
		if re.MatchString(d) {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
