// Package builder resolves and builds the image for a target state.
//
// Nix-inspired reuse: a state's built image is tagged by a content hash of its
// inputs (base + patch + overlays + env). Identical inputs produce an identical
// tag, so the build is skipped and the existing image reused. Templates that
// share a base reuse its layers through the engine's build cache.
//
// Four build kinds, cheapest first:
//
//	image    the state runs a prebuilt image (base image, or a per-state
//	         override). No build; the engine pulls/reuses.
//	overlay  an image plus config files baked in via a tiny generated
//	         Dockerfile, so the running container needs no volume mounts.
//	source   a git checkout at a pinned commit, the state's patch applied,
//	         built from the repo's Dockerfile.
//	build    a Dockerfile + source inside the template folder (simulations,
//	         devices, anything with no public image).
package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// Label keys stamped on every image vulnsuite builds.
const (
	LabelID       = "dev.vulnsuite.id"
	LabelState    = "dev.vulnsuite.state"
	LabelHash     = "dev.vulnsuite.hash"
	LabelVulnRefs = "dev.vulnsuite.vuln_refs"
	LabelKind     = "dev.vulnsuite.build_kind"
	// LabelSidecar names the sidecar a built sidecar image is for. Such an
	// image carries no LabelState: every state that runs the sidecar from its
	// build shares it.
	LabelSidecar = "dev.vulnsuite.sidecar"
)

// Resolved is the outcome of resolving a state's image.
type Resolved struct {
	ID        string        `json:"id"`
	State     string        `json:"state"`
	Ref       string        `json:"ref"`        // the image to run
	BuildKind string        `json:"build_kind"` // image | overlay | source | build
	Built     bool          `json:"built"`      // a build happened (vs reused/pulled)
	Pulled    bool          `json:"pulled"`
	Elapsed   time.Duration `json:"elapsed"`
	// Sidecar names the sidecar this image is for ("" for the target).
	Sidecar string `json:"sidecar,omitempty"`
	// Sidecars are the images of the state's built sidecars (BuildKind
	// build), resolved together with the target, in declared order. A
	// sidecar that runs a prebuilt image is not listed: the runner pulls it
	// when it starts the sidecar.
	Sidecars []*Resolved `json:"sidecars,omitempty"`
}

// Options tune a build.
type Options struct {
	// Pull missing prebuilt images (default true via the CLI).
	Pull bool
	// NoCache disables the engine's layer cache.
	NoCache bool
	// Force rebuilds even when the content-addressed tag already exists.
	Force bool
	// Platform, e.g. linux/amd64 (empty = engine default). It is used for
	// pulls and builds, and an existing image is reused only when it is for
	// this platform.
	Platform string
	// Output receives build/pull progress (nil = discard).
	Output io.Writer
}

// Builder builds target images on an engine.
type Builder struct {
	Engine engine.Engine
	// Git is the git binary used for source bases (default "git").
	Git string

	// pullLocks serialises the exists-or-pull step per image and platform,
	// so parallel jobs sharing a base (ResolveAll) pull it once instead of
	// each seeing it missing and pulling it again.
	pullLocks sync.Map // ref + "\x00" + platform -> *sync.Mutex
	// buildLocks serialises the build of a built sidecar's tag, which every
	// state running the sidecar shares, so parallel jobs build it once.
	buildLocks sync.Map // tag + "\x00" + platform -> *sync.Mutex
	// forcedTags are the sidecar tags rebuilt under Options.Force, so the
	// other state reuses the fresh build instead of forcing another one.
	forcedTags sync.Map // tag + "\x00" + platform -> true
}

// pullIfMissing pulls ref for platform unless it is already present,
// reporting whether it pulled. Concurrent calls for the same image wait for
// each other, and the later ones find it present.
func (b *Builder) pullIfMissing(ctx context.Context, ref, platform string, out io.Writer) (bool, error) {
	l, _ := b.pullLocks.LoadOrStore(ref+"\x00"+platform, &sync.Mutex{})
	mu := l.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	exists, err := b.Engine.ImageExists(ctx, ref, platform)
	if err != nil || exists {
		return false, err
	}
	if err := b.Engine.ImagePull(ctx, ref, platform, out); err != nil {
		return false, err
	}
	return true, nil
}

// New returns a Builder on eng.
func New(eng engine.Engine) *Builder { return &Builder{Engine: eng, Git: "git"} }

// Resolve makes sure the image for c/state exists locally, building or
// pulling as needed, and returns what to run. The images of the state's
// built sidecars are built (or reused) with it, in Resolved.Sidecars.
func (b *Builder) Resolve(ctx context.Context, c *contract.Contract, state string, opts Options) (*Resolved, error) {
	started := time.Now()
	res, err := b.resolveTarget(ctx, c, state, opts)
	if err != nil {
		return nil, err
	}
	st := c.States[state]
	for _, sc := range c.Service.Sidecars {
		if !st.BuildsSidecar(sc) {
			continue
		}
		sr, err := b.resolveSidecar(ctx, c, state, sc, opts)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: sidecar %s (build): %w", c.ID(), state, sc.Name, err)
		}
		res.Sidecars = append(res.Sidecars, sr)
	}
	res.Elapsed = time.Since(started)
	return res, nil
}

// resolveTarget is Resolve for the target's own image.
func (b *Builder) resolveTarget(ctx context.Context, c *contract.Contract, state string, opts Options) (*Resolved, error) {
	started := time.Now()
	st, err := c.State(state)
	if err != nil {
		return nil, err
	}
	kind := c.BuildKind(state)
	res := &Resolved{ID: c.ID(), State: state, BuildKind: kind}
	defer func() { res.Elapsed = time.Since(started) }()

	if kind == contract.BuildKindImage {
		ref := st.EffectiveImage(c.Base)
		if ref == "" {
			return nil, fmt.Errorf("%s/%s: cannot resolve an image", c.ID(), state)
		}
		res.Ref = ref
		if opts.Pull {
			pulled, err := b.pullIfMissing(ctx, ref, opts.Platform, opts.Output)
			if err != nil {
				return nil, err
			}
			res.Pulled = pulled
			return res, nil
		}
		exists, err := b.Engine.ImageExists(ctx, ref, opts.Platform)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("%s/%s: image %s%s is not present and pulling is disabled", c.ID(), state, ref, forPlatform(opts.Platform))
		}
		return res, nil
	}

	tag := c.ImageTag(state)
	res.Ref = tag
	if !opts.Force {
		// The content hash does not cover the platform: reuse the tag only
		// when it was built for the platform wanted now (the host's when none
		// is set), so an emulated build is not reused natively or vice versa.
		exists, err := b.Engine.ImageExists(ctx, tag, b.reusePlatform(ctx, opts.Platform))
		if err != nil {
			return nil, err
		}
		if exists {
			return res, nil
		}
	}
	var buildErr error
	switch kind {
	case contract.BuildKindOverlay:
		buildErr = b.buildOverlay(ctx, c, st, tag, opts)
	case contract.BuildKindBuild:
		buildErr = b.buildLocal(ctx, c, st, tag, opts)
	case contract.BuildKindSource:
		buildErr = b.buildSource(ctx, c, st, tag, opts)
	default:
		buildErr = fmt.Errorf("unknown build kind %q", kind)
	}
	if buildErr != nil {
		return nil, fmt.Errorf("%s/%s (%s build): %w", c.ID(), state, kind, buildErr)
	}
	res.Built = true
	return res, nil
}

// resolveSidecar makes sure the image of a built sidecar exists, building it
// from its context unless its content-addressed tag is already there for the
// platform wanted. States that run the sidecar from its build share the tag;
// concurrent resolutions of it (ResolveAll, both states) build it once.
func (b *Builder) resolveSidecar(ctx context.Context, c *contract.Contract, state string, sc contract.Sidecar, opts Options) (*Resolved, error) {
	started := time.Now()
	tag := c.SidecarTag(sc)
	res := &Resolved{ID: c.ID(), State: state, Sidecar: sc.Name, Ref: tag, BuildKind: contract.BuildKindBuild}
	defer func() { res.Elapsed = time.Since(started) }()

	l, _ := b.buildLocks.LoadOrStore(tag+"\x00"+opts.Platform, &sync.Mutex{})
	mu := l.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	if !opts.Force || b.forced(tag, opts.Platform) {
		// As for a state's built tag: reuse it only when it was built for
		// the platform wanted now.
		exists, err := b.Engine.ImageExists(ctx, tag, b.reusePlatform(ctx, opts.Platform))
		if err != nil {
			return nil, err
		}
		if exists {
			return res, nil
		}
	}
	ctxDir, err := c.TemplatePath(sc.Build.Context)
	if errors.Is(err, contract.ErrPathEscapes) {
		return nil, fmt.Errorf("build context: %w", err)
	}
	if info, serr := os.Stat(ctxDir); err != nil || serr != nil || !info.IsDir() {
		return nil, fmt.Errorf("build context %s not found", sc.Build.Context)
	}
	dockerfile := sc.Build.DockerfilePath()
	stream := newBuildContext(ctxDir).stream(dockerfile)
	err = b.Engine.ImageBuild(ctx, engine.BuildOptions{
		Context:    stream,
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		BuildArgs:  sc.Build.BuildArgs,
		NoCache:    opts.NoCache,
		Labels: map[string]string{
			LabelID:                                c.ID(),
			LabelSidecar:                           sc.Name,
			LabelHash:                              c.SidecarHash(sc),
			LabelKind:                              contract.BuildKindBuild,
			"org.opencontainers.image.title":       c.ID() + " (sidecar " + sc.Name + ")",
			"org.opencontainers.image.description": c.Metadata.Summary,
		},
		Platform: opts.Platform,
	}, opts.Output)
	if cerr := stream.Close(); cerr != nil {
		return nil, fmt.Errorf("build context: %w", cerr)
	}
	if err != nil {
		return nil, err
	}
	if opts.Force {
		b.forcedTags.Store(tag+"\x00"+opts.Platform, true)
	}
	res.Built = true
	return res, nil
}

// forced reports whether tag was already rebuilt for platform by this
// Builder under Force, so the other state that shares a built sidecar reuses
// that build instead of rebuilding it again.
func (b *Builder) forced(tag, platform string) bool {
	_, ok := b.forcedTags.Load(tag + "\x00" + platform)
	return ok
}

// reusePlatform is the platform an existing built image must match: the
// requested one, else the daemon's own (empty when it cannot be determined,
// which accepts any).
func (b *Builder) reusePlatform(ctx context.Context, platform string) string {
	if platform != "" {
		return platform
	}
	host, err := b.Engine.Info(ctx)
	if err != nil || host.Arch == "" {
		return ""
	}
	hostOS := host.OS
	if hostOS == "" {
		hostOS = "linux"
	}
	return hostOS + "/" + host.Arch
}

func forPlatform(platform string) string {
	if platform == "" {
		return ""
	}
	return " for " + platform
}

func (b *Builder) labels(c *contract.Contract, st *contract.State, kind string) map[string]string {
	return map[string]string{
		LabelID:                                c.ID(),
		LabelState:                             st.Name,
		LabelHash:                              c.ContentHash(st.Name),
		LabelVulnRefs:                          strings.Join(c.Metadata.VulnRefs, ","),
		LabelKind:                              kind,
		"org.opencontainers.image.title":       c.ID() + " (" + st.Name + ")",
		"org.opencontainers.image.description": c.Metadata.Summary,
	}
}

func (b *Builder) build(ctx context.Context, c *contract.Contract, st *contract.State, kind, tag, dockerfile string,
	bc *buildContext, opts Options) error {
	stream := bc.stream(dockerfile)
	err := b.Engine.ImageBuild(ctx, engine.BuildOptions{
		Context:    stream,
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		BuildArgs:  c.Base.BuildArgs,
		NoCache:    opts.NoCache,
		Labels:     b.labels(c, st, kind),
		Platform:   opts.Platform,
	}, opts.Output)
	// An error writing the context (an unreadable file, a bad .dockerignore)
	// is the real cause of a build that then failed on a truncated stream.
	if cerr := stream.Close(); cerr != nil {
		return fmt.Errorf("build context: %w", cerr)
	}
	return err
}

// -- overlay ------------------------------------------------------------------

func (b *Builder) buildOverlay(ctx context.Context, c *contract.Contract, st *contract.State, tag string, opts Options) error {
	baseRef := st.EffectiveImage(c.Base)
	if baseRef == "" {
		return errors.New("overlay needs an image base")
	}
	if opts.Pull {
		if _, err := b.pullIfMissing(ctx, baseRef, opts.Platform, opts.Output); err != nil {
			return err
		}
	}
	mc := newBuildContext("")
	var entries []overlayEntry
	for i, o := range st.Overlay {
		if err := contract.CheckOverlayDest(o.Dest, true); err != nil {
			return fmt.Errorf("overlay dest %q: %w", o.Dest, err)
		}
		data, err := readTemplateFile(c, o.Src)
		if err != nil {
			return fmt.Errorf("overlay %s: %w", o.Src, err)
		}
		mode, err := modeOf(o.Mode)
		if err != nil {
			return err
		}
		local := fmt.Sprintf("overlay_%d_%s", i, path.Base(o.Dest))
		mc.add(local, data, mode)
		entries = append(entries, overlayEntry{local: local, dest: o.Dest})
	}
	df, err := overlayDockerfile(baseRef, entries, st.Environment, '\\')
	if err != nil {
		return err
	}
	mc.add("Dockerfile", []byte(df), 0o644)
	return b.build(ctx, c, st, contract.BuildKindOverlay, tag, "Dockerfile", mc, opts)
}

// -- local build (simulations, devices) ---------------------------------------

func (b *Builder) buildLocal(ctx context.Context, c *contract.Contract, st *contract.State, tag string, opts Options) error {
	// The context is resolved (symlinks followed) and must stay inside the
	// template folder; the tree walk below then never follows a symlink.
	ctxDir, err := c.TemplatePath(c.Base.Context)
	if errors.Is(err, contract.ErrPathEscapes) {
		return fmt.Errorf("build context: %w", err)
	}
	if info, serr := os.Stat(ctxDir); err != nil || serr != nil || !info.IsDir() {
		return fmt.Errorf("build context %s not found", c.Base.Context)
	}
	src := ctxDir
	if st.Patch != "" {
		// A patch needs a real directory to apply to: work on a copy.
		tmp, err := os.MkdirTemp("", "vulnsuite-ctx-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		src = filepath.Join(tmp, "ctx")
		if err := copyTree(ctxDir, src); err != nil {
			return err
		}
		patch, err := c.TemplatePath(st.Patch)
		if err != nil {
			return fmt.Errorf("patch: %w", err)
		}
		if err := b.applyPatch(ctx, src, patch); err != nil {
			return err
		}
	}
	mc := newBuildContext(src)
	if err := addOverlays(mc, c, st); err != nil {
		return err
	}
	dockerfile := c.Base.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if err := bakeEnv(mc, dockerfile, st.Environment); err != nil {
		return err
	}
	return b.build(ctx, c, st, contract.BuildKindBuild, tag, dockerfile, mc, opts)
}

// -- source + patch -----------------------------------------------------------

func (b *Builder) buildSource(ctx context.Context, c *contract.Contract, st *contract.State, tag string, opts Options) error {
	if c.Base.Kind != contract.BaseSource {
		return errors.New("a patch needs a source base")
	}
	tmp, err := os.MkdirTemp("", "vulnsuite-src-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := validateRepoURL(c.Base.Repo); err != nil {
		return err
	}
	repo := filepath.Join(tmp, "src")
	if err := b.checkoutSource(ctx, c.Base.Repo, c.Base.Commit, repo); err != nil {
		return err
	}
	if st.Patch != "" {
		patch, err := c.TemplatePath(st.Patch)
		if err != nil {
			return fmt.Errorf("patch: %w", err)
		}
		if err := b.applyPatch(ctx, repo, patch); err != nil {
			return err
		}
	}
	mc := newBuildContext(repo)
	if err := addOverlays(mc, c, st); err != nil {
		return err
	}
	dockerfile := c.Base.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if err := bakeEnv(mc, dockerfile, st.Environment); err != nil {
		return err
	}
	return b.build(ctx, c, st, contract.BuildKindSource, tag, dockerfile, mc, opts)
}

// readTemplateFile reads a file the contract references, refusing any path
// (.., absolute, or a symlink) that resolves outside the template folder.
func readTemplateFile(c *contract.Contract, rel string) ([]byte, error) {
	p, err := c.TemplatePath(rel)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	return os.ReadFile(p)
}

// addOverlays writes a source/build state's overlay files into the build
// context; dest is a path inside the context.
func addOverlays(mc *buildContext, c *contract.Contract, st *contract.State) error {
	for _, o := range st.Overlay {
		if err := contract.CheckOverlayDest(o.Dest, false); err != nil {
			return fmt.Errorf("overlay dest %q: %w", o.Dest, err)
		}
		data, err := readTemplateFile(c, o.Src)
		if err != nil {
			return fmt.Errorf("overlay %s: %w", o.Src, err)
		}
		mode, err := modeOf(o.Mode)
		if err != nil {
			return err
		}
		mc.add(strings.TrimPrefix(path.Clean("/"+o.Dest), "/"), data, mode)
	}
	return nil
}

// bakeEnv appends the state's environment to the Dockerfile so the published
// image is self-contained (the runner passes it at run time as well).
func bakeEnv(mc *buildContext, dockerfile string, env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	f, ok, err := mc.readFile(dockerfile)
	if err != nil {
		return fmt.Errorf("read %s: %w", dockerfile, err)
	}
	if !ok {
		return fmt.Errorf("build context has no %s", dockerfile)
	}
	extra, err := overlayDockerfile("", nil, env, escapeToken(f.data))
	if err != nil {
		return err
	}
	extra = strings.TrimPrefix(extra, "FROM \n")
	data := append([]byte{}, f.data...)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(extra)...)
	mc.add(dockerfile, data, f.mode)
	return nil
}

// lfOnly makes git write files with LF line endings whatever the host's
// configuration: the tree is built into a Linux image, and a Windows git with
// core.autocrlf=true would otherwise check scripts out with CRLF (and the LF
// patch would then no longer match them).
var lfOnly = []string{"-c", "core.autocrlf=false", "-c", "core.eol=lf"}

// checkoutSource clones repo into dst and checks out commit, with LF line
// endings on every host.
func (b *Builder) checkoutSource(ctx context.Context, repo, commit, dst string) error {
	// "--" stops the repo value being read as an option.
	clone := append(append([]string{}, lfOnly...), "clone", "--filter=blob:none", "--no-checkout", "--", repo, dst)
	if out, err := b.git(ctx, "", 10*time.Minute, clone...); err != nil {
		return fmt.Errorf("clone %s: %s", repo, tail(out))
	}
	checkout := append(append([]string{}, lfOnly...), "checkout", "--quiet", commit)
	if out, err := b.git(ctx, dst, 2*time.Minute, checkout...); err != nil {
		return fmt.Errorf("checkout %s: %s", commit, tail(out))
	}
	return nil
}

func (b *Builder) applyPatch(ctx context.Context, dir, patch string) error {
	// A patch is untrusted template content applied on the host. Refuse any
	// hunk that targets an absolute path or escapes the source tree with "..".
	if err := patchStaysInTree(patch); err != nil {
		return fmt.Errorf("apply %s: %w", filepath.Base(patch), err)
	}
	// git apply resolves the patch's paths against the repository containing
	// the working directory. cmd.Dir is already dir; capping repository
	// discovery at dir keeps a copied build context (which is not itself a
	// repository) from being read as part of an enclosing one, such as a
	// TMPDIR inside a checkout. Without --unsafe-paths, git apply refuses
	// absolute paths, ".." and writes beyond a symlink.
	// lfOnly: the context is built into a Linux image, so a Windows host's
	// git must not write the patched lines with CRLF.
	ceiling := "GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir)
	out, err := b.gitEnv(ctx, dir, 2*time.Minute, []string{ceiling}, append(append([]string{}, lfOnly...), "apply", "--", patch)...)
	if err == nil {
		return nil
	}
	gitErr := fmt.Errorf("apply %s: %s", filepath.Base(patch), tail(out))
	// Fallback for patches git apply will not take (it allows no fuzz): GNU
	// patch only. GNU patch (2.7 and later) refuses on its own to write to an
	// absolute path, through "..", or through a symbolic link, on top of the
	// patchStaysInTree scan above. Any other patch (BSD patch on macOS) does
	// not promise that, so it is not used: the build fails closed with git's
	// error.
	if !isGNUPatch(ctx) {
		return gitErr
	}
	cmd := exec.CommandContext(ctx, "patch", patchFallbackArgs(dir, patch)...)
	pout, perr := cmd.CombinedOutput()
	if perr != nil {
		return fmt.Errorf("%w; patch fallback: %s", gitErr, tail(string(pout)))
	}
	return nil
}

// patchFallbackArgs is the GNU patch command line that applies patch inside
// dir. The paths are passed as option values, made absolute so neither can
// read as an option, and "--" ends the options so nothing after them is
// parsed as one.
func patchFallbackArgs(dir, patch string) []string {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if abs, err := filepath.Abs(patch); err == nil {
		patch = abs
	}
	return []string{"-p1", "--forward", "--batch", "--directory=" + dir, "--input=" + patch, "--"}
}

// isGNUPatch reports whether the patch on PATH is GNU patch.
func isGNUPatch(ctx context.Context) bool {
	if _, err := exec.LookPath("patch"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "patch", "--version").CombinedOutput()
	return err == nil && strings.Contains(string(out), "GNU patch")
}

// patchStaysInTree rejects a unified diff whose target paths are absolute or
// contain a ".." segment, so applying it cannot write outside the source tree.
func patchStaysInTree(patch string) error {
	data, err := os.ReadFile(patch)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "--- ") && !strings.HasPrefix(line, "+++ ") {
			continue
		}
		p := strings.TrimSpace(line[4:])
		if i := strings.IndexAny(p, "\t "); i >= 0 { // strip trailing timestamp
			p = p[:i]
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "a/"), "b/")
		if p == "" || p == "/dev/null" {
			continue
		}
		if strings.HasPrefix(p, "/") {
			return fmt.Errorf("patch targets an absolute path %q", p)
		}
		for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
			if seg == ".." {
				return fmt.Errorf("patch escapes the source tree via %q", p)
			}
		}
	}
	return nil
}

func (b *Builder) git(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	return b.gitEnv(ctx, dir, timeout, nil, args...)
}

func (b *Builder) gitEnv(ctx context.Context, dir string, timeout time.Duration, env []string, args ...string) (string, error) {
	git := b.Git
	if git == "" {
		git = "git"
	}
	if _, err := exec.LookPath(git); err != nil {
		return "", fmt.Errorf("git is required for source bases and patches: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// Templates are untrusted. Restrict git to network transports (no ext::/
	// fd:: which execute arbitrary commands, no local file:: side effects) and
	// never prompt for credentials on the host.
	cmd.Env = append(os.Environ(),
		"GIT_ALLOW_PROTOCOL=https:http:git:ssh",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PROTOCOL_FROM_USER=0",
	)
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// validateRepoURL rejects repo values that a malicious template could use to
// run commands on the host at clone time (git ext::/fd:: transports, option
// injection via a leading dash) or reach the local filesystem (file://, bare
// paths). Only real remote URLs are allowed.
func validateRepoURL(repo string) error {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return errors.New("base.repo is empty")
	}
	if strings.HasPrefix(repo, "-") {
		return fmt.Errorf("base.repo %q may not start with '-'", repo)
	}
	if strings.Contains(repo, "::") {
		return fmt.Errorf("base.repo %q uses a disallowed git transport; use an https, git or ssh URL", repo)
	}
	if i := strings.Index(repo, "://"); i >= 0 {
		switch strings.ToLower(repo[:i]) {
		case "https", "http", "git", "ssh":
			return nil
		default:
			return fmt.Errorf("base.repo scheme %q is not allowed; use https, git or ssh", repo[:i])
		}
	}
	// scp-like remote (user@host:path), not a local path.
	if strings.Contains(repo, "@") && strings.Contains(repo, ":") &&
		!strings.HasPrefix(repo, "/") && !strings.HasPrefix(repo, ".") {
		return nil
	}
	return fmt.Errorf("base.repo %q is not an allowed remote URL (use https://, git://, ssh:// or user@host:path)", repo)
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return "..." + s[len(s)-300:]
	}
	return s
}

// modeOf is the tar-header mode of an overlay file. The mode is template
// input that reaches the build context directly, so it is re-checked here:
// only permission bits ("0755"), never setuid/setgid/sticky or file type.
func modeOf(mode string) (int64, error) {
	if mode == "" {
		return 0o644, nil
	}
	if !modeRe.MatchString(mode) {
		return 0, fmt.Errorf("overlay mode %q must be an octal mode like 0644", mode)
	}
	m, _ := strconv.ParseInt(mode, 8, 64)
	if m == 0 {
		return 0o644, nil
	}
	return m, nil
}

// copyTree copies a build context so a patch can be applied to it. Symlinks
// are copied as symlinks (never followed: they may point outside the folder).
// Permission bits are kept (the context's tar headers carry them) rather than
// left to the umask; only owner rwx is added to directories, so the patch can
// still be applied and the copy removed.
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			return os.Chmod(target, info.Mode().Perm()|0o700)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, info.Mode().Perm()); err != nil {
			return err
		}
		return os.Chmod(target, info.Mode().Perm())
	})
}

// -- many at once ---------------------------------------------------------------

// Job is one (contract, state) to resolve.
type Job struct {
	Contract *contract.Contract
	State    string
	// Platform overrides Options.Platform for this job (e.g. the emulation
	// platform its target's requires.arch calls for); empty = Options.Platform.
	Platform string
}

// Outcome pairs a job with its result.
type Outcome struct {
	Job      Job
	Resolved *Resolved
	Err      error
	Log      string // the engine's build/pull output
}

// ResolveAll resolves every job with at most `parallel` running at once.
// Each job's engine output is captured in Outcome.Log; onDone (may be nil) is
// called as each job finishes, in completion order.
func (b *Builder) ResolveAll(ctx context.Context, jobs []Job, parallel int, opts Options, onDone func(Outcome)) []Outcome {
	if parallel < 1 {
		parallel = 1
	}
	results := make([]Outcome, len(jobs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, j := range jobs {
		if ctx.Err() != nil {
			results[i] = Outcome{Job: j, Err: ctx.Err()}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, j Job) {
			defer wg.Done()
			defer func() { <-sem }()
			var log strings.Builder
			o := opts
			o.Output = &log
			if j.Platform != "" {
				o.Platform = j.Platform
			}
			res, err := b.Resolve(ctx, j.Contract, j.State, o)
			out := Outcome{Job: j, Resolved: res, Err: err, Log: log.String()}
			results[i] = out
			if onDone != nil {
				mu.Lock()
				onDone(out)
				mu.Unlock()
			}
		}(i, j)
	}
	wg.Wait()
	return results
}

// PublishRef is the registry reference an image is pushed as:
// <registry>/<id>:<state> (plus <state>-<hash> for the immutable tag).
func PublishRef(registry, id, state string) string {
	return strings.TrimSuffix(registry, "/") + "/" + id + ":" + state
}

// Publish tags a built image into registry and pushes both the moving
// (:state) and immutable (:state-hash) tags.
func (b *Builder) Publish(ctx context.Context, c *contract.Contract, state, registry string, out io.Writer) ([]string, error) {
	local := c.ImageRef(state)
	moving := PublishRef(registry, c.ID(), state)
	immutable := moving + "-" + c.ContentHash(state)
	var pushed []string
	for _, ref := range []string{immutable, moving} {
		if err := b.Engine.ImageTag(ctx, local, ref); err != nil {
			return pushed, fmt.Errorf("tag %s: %w", ref, err)
		}
		if err := b.Engine.ImagePush(ctx, ref, out); err != nil {
			return pushed, err
		}
		pushed = append(pushed, ref)
	}
	return pushed, nil
}

// PublishSidecar pushes a built sidecar's image like Publish pushes a
// state's: tagged <registry>/<id>:sidecar-<name>-<hash> (immutable) and
// <registry>/<id>:sidecar-<name> (moving). A sidecar that runs a prebuilt
// image has nothing of vulnsuite's to push and is refused.
func (b *Builder) PublishSidecar(ctx context.Context, c *contract.Contract, sc contract.Sidecar, registry string, out io.Writer) ([]string, error) {
	if sc.Build == nil {
		return nil, fmt.Errorf("sidecar %s runs a prebuilt image; only built sidecars are published", sc.Name)
	}
	local := c.SidecarTag(sc)
	moving := PublishRef(registry, c.ID(), contract.SidecarTagPrefix+sc.Name)
	immutable := moving + "-" + c.SidecarHash(sc)
	var pushed []string
	for _, ref := range []string{immutable, moving} {
		if err := b.Engine.ImageTag(ctx, local, ref); err != nil {
			return pushed, fmt.Errorf("tag %s: %w", ref, err)
		}
		if err := b.Engine.ImagePush(ctx, ref, out); err != nil {
			return pushed, err
		}
		pushed = append(pushed, ref)
	}
	return pushed, nil
}
