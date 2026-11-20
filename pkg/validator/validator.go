// Package validator is the semantic lint for target templates: structure is
// handled when a contract is parsed; this catches templates that are *wrong*
// rather than malformed.
package validator

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/loader"
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
	// Nmap, when set, cross-checks nmap: detected_by refs against a directory
	// of nmap NSE scripts.
	Nmap *scanners.Index
	// CategoryOf, when set, returns a contract's product-surface category (the
	// top directory level). It lets the group check flag a family that spans
	// more than one surface; when nil, that check is skipped.
	CategoryOf func(*contract.Contract) string
}

// Check lints one contract.
func (v *Validator) Check(c *contract.Contract) []Finding {
	var out []Finding
	out = append(out, v.pinning(c)...)
	out = append(out, v.filesExist(c)...)
	out = append(out, v.states(c)...)
	out = append(out, v.verify(c)...)
	out = append(out, v.ports(c)...)
	out = append(out, v.portRefs(c)...)
	out = append(out, v.shadowed(c)...)
	out = append(out, v.provenance(c)...)
	out = append(out, v.fidelity(c)...)
	out = append(out, v.requires(c)...)
	out = append(out, v.hostAccess(c)...)
	out = append(out, v.sequences(c)...)
	out = append(out, v.verification(c)...)
	return out
}

// verification checks metadata.verification against its evidence. It never
// relaxes another rule: an unverified contract needs every static check.
func (v *Validator) verification(c *contract.Contract) []Finding {
	var out []Finding
	m := c.Metadata
	if c.IsUnverified() {
		out = append(out, Finding{Warning, c.ID(), "unverified-target",
			"verification: unverified -- no one has run this target's states yet; run `vulnsuite stamp -t " + c.ID() +
				"` on a host that meets its requires to verify it and record the evidence"})
	}
	hostSpecific := len(c.Requires.CPUFlags) > 0 || c.Requires.Probe != nil
	if m.Verification == contract.VerificationVerified && hostSpecific && m.VerifiedOn == nil {
		out = append(out, Finding{Warning, c.ID(), "verified-no-evidence",
			"verification: verified, but requires needs specific hardware and verified_on records no run; " +
				"run `vulnsuite stamp` on such a host, or set verification: unverified"})
	}
	if vo := m.VerifiedOn; vo != nil {
		for _, st := range vo.States {
			if !c.HasState(st) {
				out = append(out, Finding{Warning, c.ID(), "verified-on-stale",
					fmt.Sprintf("verified_on lists state %q, which the template no longer declares; re-run `vulnsuite stamp`", st)})
			}
		}
		var unchecked []string
		for _, f := range c.Requires.CPUFlags {
			if !slices.Contains(vo.CPUFlags, f) {
				unchecked = append(unchecked, f)
			}
		}
		if len(unchecked) > 0 && !c.IsUnverified() {
			out = append(out, Finding{Warning, c.ID(), "verified-on-stale",
				fmt.Sprintf("requires.cpu_flags %s were not part of the verified_on run; re-run `vulnsuite stamp` on a host that has them",
					strings.Join(unchecked, ", "))})
		}
	}
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
	// cpu_flags rule out emulation (qemu does not provide them), so an
	// explicit emulation: true next to them is contradicted and ignored.
	if len(c.Requires.CPUFlags) > 0 && c.Requires.Emulation != nil && *c.Requires.Emulation {
		out = append(out, Finding{Warning, c.ID(), "cpu-flags-with-emulation",
			"requires.emulation is true but requires.cpu_flags is set, which rules emulation out (qemu does not provide CPU flags); drop emulation: true"})
	}
	return out
}

// CheckAll lints a set of contracts, also catching duplicate ids and the
// cross-contract variant-group rules.
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
	out = append(out, v.groupChecks(contracts)...)
	return out
}

// groupChecks enforces the variant-group rules over a set of contracts: one
// primary per group, unique variants, no group/id collision, a single product
// surface per group, and consistent vuln_refs. It operates on whatever set it
// is given; `validate` expands groups so a family is seen whole.
func (v *Validator) groupChecks(contracts []*contract.Contract) []Finding {
	var out []Finding
	ids := map[string]bool{}
	groups := map[string][]*contract.Contract{}
	var order []string
	for _, c := range contracts {
		ids[c.ID()] = true
		h := c.Metadata.Group
		if h == "" {
			continue
		}
		if _, seen := groups[h]; !seen {
			order = append(order, h)
		}
		groups[h] = append(groups[h], c)
	}
	for _, h := range order {
		members := groups[h]
		if ids[h] {
			out = append(out, Finding{Error, h, "group-id-collision",
				fmt.Sprintf("group handle %q is also a template id; a group handle must not equal any id", h)})
		}
		// Unique variants (every non-primary member of a multi-member group
		// needs one); a single-member group is a nickname and needs none.
		if len(members) > 1 {
			var primaries []string
			for _, m := range members {
				if m.Metadata.Primary {
					primaries = append(primaries, m.ID())
				}
			}
			switch {
			case len(primaries) == 0:
				out = append(out, Finding{Error, h, "group-no-primary",
					fmt.Sprintf("group %q has %d members but none is primary; mark exactly one primary: true", h, len(members))})
			case len(primaries) > 1:
				out = append(out, Finding{Error, h, "group-multiple-primaries",
					fmt.Sprintf("group %q has %d primaries (%s); exactly one member may be primary", h, len(primaries), strings.Join(primaries, ", "))})
			}
			seenVar := map[string]string{}
			for _, m := range members {
				vr := m.Metadata.Variant
				if vr == "" {
					if !m.Metadata.Primary {
						out = append(out, Finding{Error, m.ID(), "group-variant-missing",
							fmt.Sprintf("member of group %q sets no variant; every non-primary member needs a unique variant", h)})
					}
					continue
				}
				if prev, dup := seenVar[vr]; dup {
					out = append(out, Finding{Error, m.ID(), "group-duplicate-variant",
						fmt.Sprintf("variant %q in group %q is also used by %s", vr, h, prev)})
				}
				seenVar[vr] = m.ID()
			}
		}
		// Single product surface per group (warn; -strict escalates it).
		if v.CategoryOf != nil && len(members) > 1 {
			cats := map[string]bool{}
			for _, m := range members {
				cats[v.CategoryOf(m)] = true
			}
			if len(cats) > 1 {
				var names []string
				for cat := range cats {
					if cat == "" {
						cat = "(root)"
					}
					names = append(names, cat)
				}
				sort.Strings(names)
				out = append(out, Finding{Warning, h, "group-multi-category",
					fmt.Sprintf("group %q spans more than one product surface (%s); a variant family should share one", h, strings.Join(names, ", "))})
			}
		}
		// Divergent vuln_refs across a group (soft warn).
		if len(members) > 1 {
			base := refKey(members[0])
			for _, m := range members[1:] {
				if refKey(m) != base {
					out = append(out, Finding{Warning, h, "group-divergent-refs",
						fmt.Sprintf("members of group %q have differing vuln_refs; variants of one vulnerability usually share them", h)})
					break
				}
			}
		}
	}
	return out
}

// refKey is an order-independent key for a contract's vuln_refs, for comparing
// whether group members cite the same references.
func refKey(c *contract.Contract) string {
	refs := append([]string{}, c.Metadata.VulnRefs...)
	sort.Strings(refs)
	return strings.Join(refs, "\x00")
}

// fullSHARe matches a full git commit id (SHA-1 or SHA-256); shortSHARe an
// abbreviated one, which can become ambiguous as the repository grows.
var (
	fullSHARe  = regexp.MustCompile(`^(?i)[0-9a-f]{40}([0-9a-f]{24})?$`)
	shortSHARe = regexp.MustCompile(`^(?i)[0-9a-f]{7,39}$`)
)

// pinning checks that every image a template runs or builds from is pinned:
// the base (image digest / full source commit), per-state image overrides and
// sidecar images (a sidecar built from the template is pinned by its
// content). An unpinned ref is an error, or a warning with
// AllowUnpinned; an abbreviated commit is always a warning.
func (v *Validator) pinning(c *contract.Contract) []Finding {
	level := Error
	if v.AllowUnpinned {
		level = Warning
	}
	var out []Finding
	switch {
	case !c.Base.Pinned():
		what := "image digest"
		if c.Base.Kind == contract.BaseSource {
			what = "source commit"
		}
		out = append(out, Finding{level, c.ID(), "unpinned-base",
			"base has no " + what + "; a template must pin its base to be reproducible on another device"})
	case c.Base.Kind == contract.BaseSource && fullSHARe.MatchString(c.Base.Commit):
	case c.Base.Kind == contract.BaseSource && shortSHARe.MatchString(c.Base.Commit):
		out = append(out, Finding{Warning, c.ID(), "short-commit",
			fmt.Sprintf("base.commit %q is an abbreviated commit id; use the full 40-character SHA so it cannot become ambiguous", c.Base.Commit)})
	case c.Base.Kind == contract.BaseSource:
		out = append(out, Finding{level, c.ID(), "unpinned-base",
			fmt.Sprintf("base.commit %q is not a commit id (a branch or tag moves); pin the full 40-character SHA", c.Base.Commit)})
	}
	for _, name := range c.DeclaredStates() {
		st := c.States[name]
		if st.Image != "" && !contract.RefPinned(st.Image, st.Digest) {
			out = append(out, Finding{level, c.ID(), "unpinned-state-image",
				fmt.Sprintf("states.%s.image %s has no digest; pin it to be reproducible on another device", name, st.Image)})
		}
		overrides := make([]string, 0, len(st.Sidecars))
		for sc := range st.Sidecars {
			overrides = append(overrides, sc)
		}
		sort.Strings(overrides)
		for _, sc := range overrides {
			ov := st.Sidecars[sc]
			if ov.Image != "" && !contract.RefPinned(ov.Image, ov.Digest) {
				out = append(out, Finding{level, c.ID(), "unpinned-sidecar",
					fmt.Sprintf("states.%s.sidecars.%s image %s has no digest; pin it to be reproducible on another device", name, sc, ov.Image)})
			}
		}
	}
	for _, sc := range c.Service.Sidecars {
		// A built sidecar is pinned by construction: its tag is the hash of
		// its context.
		if sc.Build == nil && !contract.RefPinned(sc.Image, sc.Digest) {
			out = append(out, Finding{level, c.ID(), "unpinned-sidecar",
				fmt.Sprintf("sidecar %s image %s has no digest; pin it to be reproducible on another device", sc.Name, sc.Image)})
		}
	}
	return out
}

func (v *Validator) filesExist(c *contract.Contract) []Finding {
	var out []Finding
	// resolve confines a template path to the folder (following symlinks);
	// a path that escapes it is reported once as path-escapes-template.
	escapes := func(what, rel string) {
		out = append(out, Finding{Error, c.ID(), "path-escapes-template",
			fmt.Sprintf("%s %s resolves outside the template folder (a symlink or .. path); templates may only reference their own files", what, rel)})
	}
	// isFile reports a regular file inside the folder; ok is false when the
	// path escapes (already reported).
	isFile := func(what, rel string) (found, ok bool) {
		p, err := c.TemplatePath(rel)
		if errors.Is(err, contract.ErrPathEscapes) {
			escapes(what, rel)
			return false, false
		}
		if err != nil {
			return false, true
		}
		info, err := os.Stat(p)
		return err == nil && info.Mode().IsRegular(), true
	}
	if c.Base.Kind == contract.BaseBuild {
		ctx, err := c.TemplatePath(c.Base.Context)
		switch {
		case errors.Is(err, contract.ErrPathEscapes):
			escapes("build context", c.Base.Context)
		case err != nil:
			out = append(out, Finding{Error, c.ID(), "missing-context",
				"build context " + c.Base.Context + " not found in the template folder"})
		default:
			if info, err := os.Stat(ctx); err != nil || !info.IsDir() {
				out = append(out, Finding{Error, c.ID(), "missing-context",
					"build context " + c.Base.Context + " not found in the template folder"})
				break
			}
			df := c.Base.Dockerfile
			if df == "" {
				df = "Dockerfile"
			}
			// A state may overlay its own Dockerfile into the context (the
			// builder reads generated files first), so the context needs one
			// only for the states that do not.
			var lacking []string
			for _, name := range c.DeclaredStates() {
				if !overlaysFile(c.States[name], df) {
					lacking = append(lacking, name)
				}
			}
			missing := func() {
				msg := "build context has no " + df
				if len(lacking) < len(c.DeclaredStates()) {
					msg += ", and it is not overlaid in: " + strings.Join(lacking, ", ")
				}
				out = append(out, Finding{Error, c.ID(), "missing-dockerfile", msg})
			}
			p, err := contract.ConfinedPath(ctx, df)
			switch {
			case errors.Is(err, contract.ErrPathEscapes):
				escapes("dockerfile", df)
			case len(lacking) == 0:
			case err != nil:
				missing()
			default:
				if info, err := os.Stat(p); err != nil || !info.Mode().IsRegular() {
					missing()
				}
			}
		}
	}
	// A built sidecar's context and Dockerfile, under the same rules as a
	// build base's (no overlay can supply a sidecar's Dockerfile).
	for _, sc := range c.Service.Sidecars {
		if sc.Build == nil {
			continue
		}
		what := "sidecar " + sc.Name + ": build context"
		ctx, err := c.TemplatePath(sc.Build.Context)
		if errors.Is(err, contract.ErrPathEscapes) {
			escapes(what, sc.Build.Context)
			continue
		}
		if info, serr := os.Stat(ctx); err != nil || serr != nil || !info.IsDir() {
			out = append(out, Finding{Error, c.ID(), "missing-context",
				what + " " + sc.Build.Context + " not found in the template folder"})
			continue
		}
		df := sc.Build.DockerfilePath()
		p, err := contract.ConfinedPath(ctx, df)
		if errors.Is(err, contract.ErrPathEscapes) {
			escapes("sidecar "+sc.Name+": dockerfile", df)
			continue
		}
		if info, serr := os.Stat(p); err != nil || serr != nil || !info.Mode().IsRegular() {
			out = append(out, Finding{Error, c.ID(), "missing-dockerfile",
				fmt.Sprintf("sidecar %s: build context %s has no %s", sc.Name, sc.Build.Context, df)})
		}
	}
	for _, name := range c.DeclaredStates() {
		st := c.States[name]
		if st.Patch != "" {
			if found, ok := isFile(name+": patch", st.Patch); ok && !found {
				out = append(out, Finding{Error, c.ID(), "missing-patch",
					fmt.Sprintf("%s: patch %s not found in the template folder", name, st.Patch)})
			}
		}
		for _, o := range st.Overlay {
			if found, ok := isFile(name+": overlay source", o.Src); ok && !found {
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

// overlaysFile reports whether st overlays a file at the build-context path
// name, compared the way the builder places overlays in the context.
func overlaysFile(st *contract.State, name string) bool {
	clean := func(p string) string { return strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(p)), "/") }
	for _, o := range st.Overlay {
		if clean(o.Dest) == clean(name) {
			return true
		}
	}
	return false
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
	// A source base builds every state from the one pinned commit, so the
	// states differ only through a patch or an overlay. One state having it is
	// enough (the usual shape: vulnerable is the commit, patched adds the fix);
	// a state image is never read on a source base and makes no difference.
	if c.Base.Kind == contract.BaseSource && c.HasPatched() {
		differs := false
		for _, name := range c.DeclaredStates() {
			st := c.States[name]
			if st.Patch != "" || len(st.Overlay) > 0 {
				differs = true
			}
		}
		if !differs {
			out = append(out, Finding{Warning, c.ID(), "source-no-diff",
				"source base but no state has a patch or overlay; vulnerable and patched build the same commit"})
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
		// The states also differ when a sidecar resolves to another image (the
		// multi-node pattern: patched swaps each node to the fixed release) or
		// when they seed different data. A built sidecar is the same image in
		// both states unless one of them overrides it.
		sameSidecars := true
		for _, sc := range c.Service.Sidecars {
			if c.SidecarImage(contract.StateVulnerable, sc) != c.SidecarImage(contract.StatePatched, sc) {
				sameSidecars = false
			}
		}
		sameSeed := fmt.Sprint(vs.Seed) == fmt.Sprint(ps.Seed)
		if sameImg && sameHash && sameCmd && sameSidecars && sameSeed {
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
			case "sequence":
				for j, step := range p.Sequence.Steps {
					for _, re := range sequenceStepRegexes(step) {
						if _, err := regexp.Compile(re); err != nil {
							out = append(out, Finding{Error, c.ID(), "bad-regex",
								fmt.Sprintf("%s: verify probe #%d step #%d (%s): %v", name, i+1, j+1, step.Kind(), err)})
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

// portRefs checks that every container port a template refers to elsewhere
// (healthcheck.tcp.port, verify http/tcp/net port) is declared in
// service.ports. An undeclared port is never published in host mode and is
// usually a typo, which otherwise surfaces only as a hang or a failed verify
// at run time. It is a warning, not an error: a template may deliberately
// probe a port only one state opens (a debug listener the vulnerable command
// line enables). A tcp probe asserting closed: true is exempt, since proving a
// port is shut needs no declaration.
func (v *Validator) portRefs(c *contract.Contract) []Finding {
	declared := map[int]bool{}
	for _, p := range c.Service.Ports {
		declared[p.Container] = true
	}
	var out []Finding
	check := func(where string, port int) {
		if port == 0 || declared[port] {
			return // 0 is the default: the primary port
		}
		out = append(out, Finding{Warning, c.ID(), "undeclared-port",
			fmt.Sprintf("%s refers to port %d, which is not declared in service.ports", where, port)})
	}
	if hc := c.Service.Healthcheck.TCP; hc != nil {
		check("healthcheck.tcp.port", hc.Port)
	}
	for _, name := range c.DeclaredStates() {
		for i, p := range c.States[name].Verify {
			where := fmt.Sprintf("%s: verify probe #%d (%s)", name, i+1, p.Kind())
			switch {
			case p.HTTP != nil:
				check(where, p.HTTP.Port)
			case p.TCP != nil && !p.TCP.Closed:
				check(where, p.TCP.Port)
			case p.Net != nil:
				check(where, p.Net.Port)
			case p.Sequence != nil:
				for j, step := range p.Sequence.Steps {
					where := fmt.Sprintf("%s: verify probe #%d (sequence) step #%d (%s)", name, i+1, j+1, step.Kind())
					switch {
					case step.HTTP != nil:
						check(where, step.HTTP.Port)
					case step.TCP != nil && !step.TCP.Closed:
						check(where, step.TCP.Port)
					case step.Net != nil:
						check(where, step.Net.Port)
					}
				}
			}
		}
	}
	return out
}

// sequenceStepRegexes returns the non-empty regexps a sequence step uses.
func sequenceStepRegexes(st contract.SequenceStep) []string {
	var res []string
	switch {
	case st.Exec != nil:
		res = append(res, st.Exec.StdoutMatches)
	case st.ExpectSanitizer != nil:
		res = append(res, st.ExpectSanitizer.Frame)
	case st.ExpectLog != nil:
		res = append(res, *st.ExpectLog)
	case st.HTTP != nil:
		res = append(res, st.HTTP.BodyMatches, st.HTTP.BodyAbsent)
		for _, k := range sortedKeys(st.HTTP.HeaderMatches) {
			res = append(res, st.HTTP.HeaderMatches[k])
		}
	case st.TCP != nil:
		res = append(res, st.TCP.BannerMatches)
	case st.Net != nil:
		for _, ns := range st.Net.Steps {
			res = append(res, ns.Expect, ns.ExpectAbsent)
		}
	}
	out := res[:0]
	for _, re := range res {
		if re != "" {
			out = append(out, re)
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sequences checks the cross-step and cross-field rules of sequence probes:
// every freeze is resumed, nothing execs in or connects to the target while it
// is frozen, exec steps name declared sidecars, expect_sanitizer has a log
// directory to read, and each sequence asserts something (with a positive
// control when it expects no sanitizer report). It also warns when
// ASAN_OPTIONS sends reports outside service.sanitizer.log_dir.
func (v *Validator) sequences(c *contract.Contract) []Finding {
	var out []Finding
	add := func(level Level, rule, format string, args ...any) {
		out = append(out, Finding{level, c.ID(), rule, fmt.Sprintf(format, args...)})
	}
	sidecars := map[string]bool{}
	for _, sc := range c.Service.Sidecars {
		sidecars[sc.Name] = true
	}
	hasLogDir := c.Service.Sanitizer != nil && c.Service.Sanitizer.LogDir != ""
	for _, name := range c.DeclaredStates() {
		for i, p := range c.States[name].Verify {
			if p.Sequence == nil {
				continue
			}
			where := fmt.Sprintf("%s: verify probe #%d (sequence)", name, i+1)
			frozen, unbalanced := false, ""
			sanitizer, positive, logs, asserts := false, false, false, false
			for j, step := range p.Sequence.Steps {
				at := fmt.Sprintf("%s step #%d", where, j+1)
				switch {
				case step.Freeze != nil:
					if frozen && unbalanced == "" {
						unbalanced = fmt.Sprintf("%s: freeze while the target is already frozen (no nested freeze)", at)
					}
					frozen = true
				case step.Resume != nil:
					if !frozen && unbalanced == "" {
						unbalanced = fmt.Sprintf("%s: resume without a freeze before it", at)
					}
					frozen = false
				case step.Exec != nil:
					if step.Exec.Asserts() {
						asserts = true
					}
					if !step.Exec.InTarget() && !sidecars[step.Exec.Container] {
						add(Error, "unknown-sidecar", "%s: exec container %q names no service sidecar", at, step.Exec.Container)
					}
					if frozen && step.Exec.InTarget() {
						add(Error, "exec-in-frozen-target",
							"%s: exec runs in the target between freeze and resume, which the engine refuses on a paused container; run it in a sidecar (container: <name>) or after resume", at)
					}
				case step.IsNetwork():
					if frozen {
						add(Error, "network-step-while-frozen",
							"%s: %s step between freeze and resume would block on the frozen target; move it before the freeze or after the resume", at, step.Kind())
					}
				case step.ExpectSanitizer != nil:
					sanitizer = true
					if step.ExpectSanitizer.Positive() {
						positive = true
					}
				case step.ExpectLog != nil:
					logs = true
				}
			}
			if frozen && unbalanced == "" {
				unbalanced = where + ": freeze without a matching resume (the target would stay paused)"
			}
			if unbalanced != "" {
				add(Error, "sequence-unbalanced-freeze", "%s", unbalanced)
			}
			if sanitizer && !hasLogDir {
				add(Error, "sanitizer-without-log-dir",
					"%s: expect_sanitizer needs service.sanitizer.log_dir, the directory the target's sanitizer writes its reports to", where)
			}
			if !sanitizer && !logs && !asserts {
				add(Error, "sequence-no-assertion",
					"%s: no expect_sanitizer, expect_log or exec step with expect_exit/stdout_matches; the sequence would prove nothing", where)
			}
			if sanitizer && !positive && !logs {
				add(Warning, "race-no-positive-control",
					"%s: expect_sanitizer: none without an expect_log; a clean result may only mean the race was never reached, so match a log line that shows it was", where)
			}
		}
	}
	if hasLogDir {
		dir := c.Service.Sanitizer.LogDir
		check := func(where string, env map[string]string) {
			opts, ok := env["ASAN_OPTIONS"]
			if !ok {
				return
			}
			lp, ok := asanLogPath(opts)
			if !ok || logPathIn(lp, dir) {
				return
			}
			add(Warning, "sanitizer-log-path",
				"%s ASAN_OPTIONS log_path=%s writes reports outside service.sanitizer.log_dir %s, where they are not read; use log_path=%s/<prefix>", where, lp, dir, dir)
		}
		check("service.environment", c.Service.Environment)
		for _, name := range c.DeclaredStates() {
			check("states."+name+".environment", c.States[name].Environment)
		}
	}
	return out
}

// asanLogPath returns the last log_path in a sanitizer options string. The
// sanitizer runtime splits options on ':', ',' and whitespace, and the last
// occurrence of a flag wins.
func asanLogPath(opts string) (string, bool) {
	var lp string
	found := false
	for _, f := range strings.FieldsFunc(opts, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if val, ok := strings.CutPrefix(f, "log_path="); ok {
			lp, found = strings.Trim(val, `"'`), true
		}
	}
	return lp, found
}

// logPathIn reports whether reports written with log_path lp (the runtime
// appends .<pid>) land directly in dir.
func logPathIn(lp, dir string) bool {
	if !strings.HasPrefix(lp, "/") {
		return false // stderr, stdout or a path relative to an unknown cwd
	}
	clean := path.Clean(lp)
	return clean != dir && path.Dir(clean) == dir
}

// shadowed reports other contract files in the template's folder: discovery
// loads one contract per folder, so the others are silently ignored.
func (v *Validator) shadowed(c *contract.Contract) []Finding {
	if c.SourcePath == "" {
		return nil
	}
	var out []Finding
	for _, other := range loader.Shadowed(c.SourcePath) {
		out = append(out, Finding{Warning, c.ID(), "shadowed-contract",
			fmt.Sprintf("folder also holds %s; a folder holds one template and only the first of %s is loaded, so the other is ignored",
				filepath.Base(other), strings.Join(loader.ContractNames, ", "))})
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
	if c.Metadata.Primary && c.Metadata.Group == "" {
		out = append(out, Finding{Warning, c.ID(), "primary-no-group",
			"primary: true has no effect without a group; set metadata.group or drop primary"})
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
	if v.Nmap != nil {
		for _, r := range scanners.Refs(c) {
			if r.Scanner == scanners.Nmap {
				if _, ok := v.Nmap.ByID[r.ID]; !ok {
					out = append(out, Finding{Warning, c.ID(), "unknown-scanner-template",
						fmt.Sprintf("detected_by names %s, which is not in %s", r.String(), v.Nmap.Root)})
				}
			}
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
