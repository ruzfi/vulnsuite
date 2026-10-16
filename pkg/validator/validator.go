// Package validator is the semantic lint for target templates: structure is
// handled when a contract is parsed; this catches templates that are *wrong*
// rather than malformed.
package validator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/scanners"
)

// Level is a finding severity.
type Level string

// Levels.
const (
	Error   Level = "error"
	Warning Level = "warning"
)

// Finding is one lint result.
type Finding struct {
	Level    Level  `json:"level"`
	Template string `json:"template"`
	Rule     string `json:"rule"`
	Message  string `json:"message"`
}

func (f Finding) String() string {
	icon := "WARN "
	if f.Level == Error {
		icon = "ERROR"
	}
	return fmt.Sprintf("%s [%s] %s: %s", icon, f.Rule, f.Template, f.Message)
}

// Validator runs the rules.
type Validator struct {
	// AllowUnpinned downgrades an unpinned base from an error to a warning
	// (useful while authoring; pin before merging).
	AllowUnpinned bool
	// Scanners, when set, cross-checks detected_by against a nuclei-templates
	// checkout (unknown ids, undeclared CVE matches).
	Scanners *scanners.Index
}

// Check lints one contract.
func (v *Validator) Check(c *contract.Contract) []Finding {
	var out []Finding
	out = append(out, v.pinning(c)...)
	out = append(out, v.filesExist(c)...)
	out = append(out, v.states(c)...)
	out = append(out, v.verify(c)...)
	out = append(out, v.ports(c)...)
	out = append(out, v.provenance(c)...)
	out = append(out, v.fidelity(c)...)
	out = append(out, v.requires(c)...)
	out = append(out, v.hostAccess(c)...)
	return out
}

func (v *Validator) requires(c *contract.Contract) []Finding {
	var out []Finding
	// A /dev/kvm device without a matching requires.kvm will hang on hosts
	// that cannot provide it instead of skipping cleanly.
	for _, d := range c.Service.Devices {
		if d == "/dev/kvm" && !c.Requires.KVM {
			out = append(out, Finding{Warning, c.ID(), "kvm-without-requires",
				"service.devices has /dev/kvm but requires.kvm is not set; add requires.kvm (and arch: [amd64]) so hosts without it skip cleanly"})
		}
	}
	return out
}

// CheckAll lints a set of contracts, also catching duplicate ids.
func (v *Validator) CheckAll(contracts []*contract.Contract) []Finding {
	var out []Finding
	seen := map[string]string{}
	for _, c := range contracts {
		if prev, ok := seen[c.ID()]; ok {
			out = append(out, Finding{Error, c.ID(), "duplicate-id", "id also used by " + prev})
		}
		seen[c.ID()] = c.SourcePath
		out = append(out, v.Check(c)...)
	}
	return out
}

func (v *Validator) pinning(c *contract.Contract) []Finding {
	if c.Base.Pinned() {
		return nil
	}
	level := Error
	if v.AllowUnpinned {
		level = Warning
	}
	what := "image digest"
	if c.Base.Kind == contract.BaseSource {
		what = "source commit"
	}
	return []Finding{{level, c.ID(), "unpinned-base",
		"base has no " + what + "; a template must pin its base to be reproducible on another device"}}
}

func (v *Validator) filesExist(c *contract.Contract) []Finding {
	var out []Finding
	isFile := func(rel string) bool {
		info, err := os.Stat(filepath.Join(c.Folder, filepath.FromSlash(rel)))
		return err == nil && info.Mode().IsRegular()
	}
	if c.Base.Kind == contract.BaseBuild {
		ctx := filepath.Join(c.Folder, filepath.FromSlash(c.Base.Context))
		if info, err := os.Stat(ctx); err != nil || !info.IsDir() {
			out = append(out, Finding{Error, c.ID(), "missing-context",
				"build context " + c.Base.Context + " not found in the template folder"})
		} else {
			df := c.Base.Dockerfile
			if df == "" {
				df = "Dockerfile"
			}
			if _, err := os.Stat(filepath.Join(ctx, filepath.FromSlash(df))); err != nil {
				out = append(out, Finding{Error, c.ID(), "missing-dockerfile",
					"build context has no " + df})
			}
		}
	}
	for _, name := range c.DeclaredStates() {
		st := c.States[name]
		if st.Patch != "" && !isFile(st.Patch) {
			out = append(out, Finding{Error, c.ID(), "missing-patch",
				fmt.Sprintf("%s: patch %s not found in the template folder", name, st.Patch)})
		}
		for _, o := range st.Overlay {
			if !isFile(o.Src) {
				out = append(out, Finding{Error, c.ID(), "missing-overlay",
					fmt.Sprintf("%s: overlay source %s not found", name, o.Src)})
			}
		}
		if st.Patch != "" && c.Base.Kind == contract.BaseImage {
			out = append(out, Finding{Error, c.ID(), "patch-needs-source",
				name + ": a patch can only be applied to a source or build base"})
		}
	}
	return out
}

// safeCaps mirrors the runner's benign-capability allowlist.
var safeCaps = map[string]bool{
	"NET_BIND_SERVICE": true, "CHOWN": true, "SETUID": true, "SETGID": true,
	"KILL": true, "FOWNER": true, "DAC_OVERRIDE": true,
}

// hostAccess warns when a template requests host-access primitives (device
// passthrough or an elevated capability), so authors and reviewers see that
// running it needs -allow-host-access and that it must be trusted.
func (v *Validator) hostAccess(c *contract.Contract) []Finding {
	var out []Finding
	if len(c.Service.Devices) > 0 {
		out = append(out, Finding{Warning, c.ID(), "host-device-access",
			fmt.Sprintf("requests host device(s) %v; this is host access, so `run` needs -allow-host-access and the template must be trusted", c.Service.Devices)})
	}
	for _, cp := range c.Service.CapAdd {
		if !safeCaps[strings.TrimPrefix(strings.ToUpper(cp), "CAP_")] {
			out = append(out, Finding{Warning, c.ID(), "elevated-capability",
				fmt.Sprintf("adds capability %q, which can escape the container; `run` needs -allow-host-access and the template must be trusted", cp)})
		}
	}
	return out
}

func (v *Validator) states(c *contract.Contract) []Finding {
	var out []Finding
	if !c.HasPatched() {
		out = append(out, Finding{Warning, c.ID(), "no-patched",
			"no patched state; a template is most useful with both, so a scanner's discrimination can be checked"})
	}
	if c.Base.Kind == contract.BaseSource {
		for _, name := range c.DeclaredStates() {
			st := c.States[name]
			if st.Patch == "" && st.Image == "" {
				out = append(out, Finding{Warning, c.ID(), "source-no-diff",
					name + ": source base but no patch or image override; vulnerable and patched may build identically"})
			}
		}
	}
	// Compare the content hashes (image + patch + overlay content + env + command),
	// not just the paths, so two overlays writing the same dest with different
	// content are correctly seen as different.
	if c.HasPatched() {
		vs, ps := c.States[contract.StateVulnerable], c.States[contract.StatePatched]
		sameImg := vs.EffectiveImage(c.Base) == ps.EffectiveImage(c.Base)
		sameHash := c.ContentHash(contract.StateVulnerable) == c.ContentHash(contract.StatePatched)
		sameCmd := fmt.Sprint(vs.Command) == fmt.Sprint(ps.Command)
		if sameImg && sameHash && sameCmd {
			out = append(out, Finding{Warning, c.ID(), "identical-states",
				"vulnerable and patched resolve to the same build"})
		}
	}
	return out
}

func (v *Validator) verify(c *contract.Contract) []Finding {
	var out []Finding
	for _, name := range c.DeclaredStates() {
		st := c.States[name]
		if len(st.Verify) == 0 {
			out = append(out, Finding{Warning, c.ID(), "no-verify",
				name + ": no verify probe; you cannot confirm the target is actually in this state"})
		}
		for i, p := range st.Verify {
			switch p.Kind() {
			case "http":
				h := p.HTTP
				if !h.Asserts() {
					out = append(out, Finding{Error, c.ID(), "empty-verify",
						fmt.Sprintf("%s: http verify probe #%d asserts nothing", name, i+1)})
				} else if !h.Strong() && name == contract.StateVulnerable {
					out = append(out, Finding{Warning, c.ID(), "weak-verify",
						name + ": verify asserts only a status; a body or header match makes the vulnerable-state claim much stronger"})
				}
				for _, re := range []string{h.BodyMatches, h.BodyAbsent} {
					if re != "" {
						if _, err := regexp.Compile(re); err != nil {
							out = append(out, Finding{Error, c.ID(), "bad-regex",
								fmt.Sprintf("%s: verify probe #%d: %v", name, i+1, err)})
						}
					}
				}
				for _, re := range h.HeaderMatches {
					if _, err := regexp.Compile(re); err != nil {
						out = append(out, Finding{Error, c.ID(), "bad-regex",
							fmt.Sprintf("%s: verify probe #%d: %v", name, i+1, err)})
					}
				}
			case "tcp":
				if p.TCP.BannerMatches != "" {
					if _, err := regexp.Compile(p.TCP.BannerMatches); err != nil {
						out = append(out, Finding{Error, c.ID(), "bad-regex",
							fmt.Sprintf("%s: verify probe #%d: %v", name, i+1, err)})
					}
				}
			case "exec":
				if p.Exec.StdoutMatches != "" {
					if _, err := regexp.Compile(p.Exec.StdoutMatches); err != nil {
						out = append(out, Finding{Error, c.ID(), "bad-regex",
							fmt.Sprintf("%s: verify probe #%d: %v", name, i+1, err)})
					}
				}
			case "net":
				for _, st := range p.Net.Steps {
					for _, re := range []string{st.Expect, st.ExpectAbsent} {
						if re != "" {
							if _, err := regexp.Compile(re); err != nil {
								out = append(out, Finding{Error, c.ID(), "bad-regex",
									fmt.Sprintf("%s: verify probe #%d: %v", name, i+1, err)})
							}
						}
					}
				}
			}
		}
	}
	return out
}

func (v *Validator) ports(c *contract.Contract) []Finding {
	var out []Finding
	if len(c.Service.Ports) == 0 {
		out = append(out, Finding{Error, c.ID(), "no-ports", "service declares no ports"})
	}
	if c.Service.Healthcheck.Empty() {
		out = append(out, Finding{Warning, c.ID(), "no-healthcheck",
			"no healthcheck; the runner cannot tell when the target is ready"})
	} else if _, err := contract.ParseDuration(c.Service.Healthcheck.Timeout, 0); err != nil {
		out = append(out, Finding{Error, c.ID(), "bad-timeout", err.Error()})
	}
	return out
}

func (v *Validator) fidelity(c *contract.Contract) []Finding {
	var out []Finding
	if c.Metadata.Fidelity == "" {
		out = append(out, Finding{Warning, c.ID(), "fidelity-unset",
			"set metadata.fidelity: real (runs the genuine software) or simulated (a stand-in); real is preferred and only sims of bare-OS/device/protocol flaws should be simulated"})
		return out
	}
	// A simulation normally builds a stand-in; a prebuilt public image as the
	// base strongly suggests this is actually the real software mislabelled.
	if c.IsSimulated() && c.Base.Kind == contract.BaseImage {
		out = append(out, Finding{Warning, c.ID(), "simulated-on-image-base",
			"fidelity: simulated but the base is a prebuilt image; if this runs the genuine software it should be fidelity: real"})
	}
	return out
}

func (v *Validator) provenance(c *contract.Contract) []Finding {
	var out []Finding
	if len(c.Metadata.VulnRefs) == 0 {
		out = append(out, Finding{Warning, c.ID(), "no-vuln-ref",
			"no vuln_refs; a scanner cross-reference has nothing to match"})
	}
	if len(c.Metadata.References) == 0 {
		out = append(out, Finding{Warning, c.ID(), "no-references",
			"no references; the vulnerability claim is unsourced"})
	}
	if c.Metadata.Detection == "scanner" && len(c.Metadata.DetectedBy) == 0 {
		out = append(out, Finding{Warning, c.ID(), "scanner-unnamed",
			"detection: scanner but detected_by names no scanner template"})
	}
	if c.Metadata.Detection == "" && len(c.Metadata.DetectedBy) == 0 {
		out = append(out, Finding{Warning, c.ID(), "no-detected-by",
			"no scanner template linked: list the ones that detect this target in detected_by (e.g. nuclei:<id>), " +
				"or set detection: custom-only if none exists upstream (and consider contributing one)"})
	}
	for _, r := range scanners.Refs(c) {
		if !r.Known() {
			out = append(out, Finding{Warning, c.ID(), "unknown-scanner",
				fmt.Sprintf("detected_by %q uses an unrecognized scanner; known scanners are nuclei and nmap", r.String())})
		}
	}
	if v.Scanners != nil {
		rep := scanners.Match(c, v.Scanners)
		for _, l := range rep.Declared {
			if l.Missing {
				out = append(out, Finding{Warning, c.ID(), "unknown-scanner-template",
					fmt.Sprintf("detected_by names %s, which is not in %s", l.Ref, v.Scanners.Root)})
			}
		}
		for _, t := range rep.Suggested {
			out = append(out, Finding{Warning, c.ID(), "undeclared-scanner-template",
				fmt.Sprintf("nuclei:%s (%s) matches this target's CVE but is not in detected_by; verify it against both states and declare it", t.ID, t.Path)})
		}
	}
	return out
}

// Worst returns the most severe level among findings ("" when none).
func Worst(findings []Finding) Level {
	var worst Level
	for _, f := range findings {
		if f.Level == Error {
			return Error
		}
		worst = Warning
	}
	return worst
}

// Count returns (errors, warnings).
func Count(findings []Finding) (errors, warnings int) {
	for _, f := range findings {
		if f.Level == Error {
			errors++
		} else {
			warnings++
		}
	}
	return
}
