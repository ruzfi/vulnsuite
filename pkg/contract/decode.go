package contract

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
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
	Image       string            `yaml:"image,omitempty"`
	Digest      string            `yaml:"digest,omitempty"`
	Patch       string            `yaml:"patch,omitempty"`
	Overlay     []OverlayFile     `yaml:"overlay,omitempty"`
	Environment map[string]string          `yaml:"environment,omitempty"`
	Command     Command                    `yaml:"command,omitempty"`
	Sidecars    map[string]SidecarOverride `yaml:"sidecars,omitempty"`
	Seed        []SeedStep                 `yaml:"seed,omitempty"`
	Verify      []Probe                    `yaml:"verify,omitempty"`
}

// SchemaError is a structural error in a contract document (the equivalent of
// a JSON-schema violation).
type SchemaError struct {
	Loc     string
	Message string
}

func (e *SchemaError) Error() string { return fmt.Sprintf("schema: %s: %s", e.Loc, e.Message) }

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,79}$`)
	vulnRefRe  = regexp.MustCompile(`^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9-]+|[A-Z]{2,8}-[A-Z0-9-]+)$`)
	cweRe      = regexp.MustCompile(`^CWE-\d+$`)
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	userRe     = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)
	capRe      = regexp.MustCompile(`^[A-Z_]+$`)
	deviceRe   = regexp.MustCompile(`^/dev/[a-zA-Z0-9/_-]+$`)
	modeRe     = regexp.MustCompile(`^0[0-7]{3}$`)
	timeoutRe  = regexp.MustCompile(`^\d+[smh]$`)
	severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	protocols  = map[string]bool{"http": true, "https": true, "tcp": true, "ssh": true, "ftp": true,
		"smtp": true, "redis": true, "mysql": true, "postgres": true}
	detections = map[string]bool{"scanner": true, "custom-only": true}
	fidelities = map[string]bool{"real": true, "simulated": true}
	hostOSes   = map[string]bool{"linux": true, "windows": true}
	arches     = map[string]bool{"amd64": true, "arm64": true, "386": true, "arm": true, "ppc64le": true, "s390x": true, "riscv64": true}
)

// Parse decodes and structurally validates a contract document. Semantic lint
// (is the template *wrong* rather than malformed?) lives in package validator.
func Parse(data []byte) (*Contract, error) {
	var raw rawContract
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("invalid YAML: %s", strings.TrimSpace(yaml.FormatError(err, false, false)))
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
	if err := c.checkStructure(); err != nil {
		return nil, err
	}
	return c, nil
}

func se(loc, format string, args ...any) error {
	return &SchemaError{Loc: loc, Message: fmt.Sprintf(format, args...)}
}

// checkStructure enforces the same rules as schemas/contract.schema.json.
func (c *Contract) checkStructure() error {
	if c.APIVersion != APIVersion {
		return se("apiVersion", "must be %q (got %q)", APIVersion, c.APIVersion)
	}
	if c.Kind != Kind {
		return se("kind", "must be %q", Kind)
	}
	m := c.Metadata
	if !idRe.MatchString(m.ID) {
		return se("metadata/id", "%q must match %s", m.ID, idRe)
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

	b := c.Base
	switch b.Kind {
	case BaseImage:
		if b.Image == "" {
			return se("base/image", "is required for kind: image")
		}
		if b.Repo != "" || b.Commit != "" || b.Context != "" || b.Dockerfile != "" || len(b.BuildArgs) > 0 {
			return se("base", "kind: image allows only image and digest")
		}
	case BaseSource:
		if b.Repo == "" || b.Commit == "" {
			return se("base", "kind: source requires repo and commit")
		}
		if b.Image != "" || b.Digest != "" || b.Context != "" {
			return se("base", "kind: source allows only repo, commit, dockerfile, build_args")
		}
	case BaseBuild:
		if b.Context == "" {
			return se("base/context", "is required for kind: build")
		}
		if b.Image != "" || b.Digest != "" || b.Repo != "" || b.Commit != "" {
			return se("base", "kind: build allows only context, dockerfile, build_args")
		}
		if path.IsAbs(b.Context) || strings.HasPrefix(path.Clean(b.Context), "..") {
			return se("base/context", "must be a relative path inside the template folder")
		}
	default:
		return se("base/kind", "%q is not one of image, source, build", b.Kind)
	}
	if b.Digest != "" && !digestRe.MatchString(b.Digest) {
		return se("base/digest", "must look like sha256:<64 hex>")
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

	s := c.Service
	if len(s.Ports) == 0 {
		return se("service/ports", "at least one port is required")
	}
	for i, p := range s.Ports {
		if p.Container < 1 || p.Container > 65535 {
			return se(fmt.Sprintf("service/ports/%d/container", i), "must be 1..65535")
		}
		if p.Protocol != "" && !protocols[p.Protocol] {
			return se(fmt.Sprintf("service/ports/%d/protocol", i), "%q is not a known protocol", p.Protocol)
		}
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
		if dangerousDevice(d) {
			return se("service/devices", "%q gives raw host disk/memory access and is never needed for a target", d)
		}
	}
	if s.Healthcheck.Timeout != "" && !timeoutRe.MatchString(s.Healthcheck.Timeout) {
		return se("service/healthcheck/timeout", "must look like 60s or 5m")
	}
	for i, sc := range s.Sidecars {
		if sc.Name == "" || sc.Image == "" {
			return se(fmt.Sprintf("service/sidecars/%d", i), "name and image are required")
		}
		if sc.Digest != "" && !digestRe.MatchString(sc.Digest) {
			return se(fmt.Sprintf("service/sidecars/%d/digest", i), "must look like sha256:<64 hex>")
		}
	}

	if len(c.States) == 0 || !c.HasState(StateVulnerable) {
		return se("states/vulnerable", "is required")
	}
	for name, st := range c.States {
		known := false
		for _, n := range StateNames {
			if n == name {
				known = true
			}
		}
		if !known {
			return se("states/"+name, "unknown state; only vulnerable and patched are allowed")
		}
		if st == nil {
			return se("states/"+name, "must be a mapping")
		}
		loc := "states/" + name
		if st.Digest != "" && !digestRe.MatchString(st.Digest) {
			return se(loc+"/digest", "must look like sha256:<64 hex>")
		}
		for i, o := range st.Overlay {
			if o.Src == "" || o.Dest == "" {
				return se(fmt.Sprintf("%s/overlay/%d", loc, i), "src and dest are required")
			}
			if o.Mode != "" && !modeRe.MatchString(o.Mode) {
				return se(fmt.Sprintf("%s/overlay/%d/mode", loc, i), "must be an octal mode like 0644")
			}
		}
		for scName, ov := range st.Sidecars {
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
			}
			if p.Exec != nil {
				n++
				if p.Exec.Run == "" {
					return se(ploc+"/exec/run", "is required")
				}
			}
			if p.TCP != nil {
				n++
				if p.TCP.Port == 0 {
					return se(ploc+"/tcp/port", "is required")
				}
			}
			if p.Net != nil {
				n++
				if len(p.Net.Steps) == 0 {
					return se(ploc+"/net/steps", "at least one step is required")
				}
			}
			if n != 1 {
				return se(ploc, "exactly one of http, exec, tcp must be set")
			}
		}
	}
	return nil
}

// dangerousDevice reports whether a /dev path grants raw host disk or memory
// access (a direct host-compromise primitive, never legitimate for a target).
// Device access that can be legitimate (e.g. /dev/kvm) is allowed here but
// still consent-gated at run time.
func dangerousDevice(d string) bool {
	d = strings.ToLower(strings.TrimRight(d, "0123456789"))
	switch d {
	case "/dev/mem", "/dev/kmem", "/dev/port", "/dev/msr":
		return true
	}
	for _, pfx := range []string{
		"/dev/sd", "/dev/hd", "/dev/vd", "/dev/xvd", "/dev/nvme", "/dev/sg",
		"/dev/dm-", "/dev/loop", "/dev/md", "/dev/mmcblk", "/dev/disk", "/dev/mapper",
	} {
		if strings.HasPrefix(d, pfx) {
			return true
		}
	}
	return false
}

