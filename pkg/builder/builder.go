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
	"path/filepath"
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
}

// Options tune a build.
type Options struct {
	// Pull missing prebuilt images (default true via the CLI).
	Pull bool
	// NoCache disables the engine's layer cache.
	NoCache bool
	// Force rebuilds even when the content-addressed tag already exists.
	Force bool
	// Platform, e.g. linux/amd64 (empty = engine default).
	Platform string
	// Output receives build/pull progress (nil = discard).
	Output io.Writer
}

// Builder builds target images on an engine.
type Builder struct {
	Engine engine.Engine
	// Git is the git binary used for source bases (default "git").
	Git string
}

// New returns a Builder on eng.
func New(eng engine.Engine) *Builder { return &Builder{Engine: eng, Git: "git"} }

// Resolve makes sure the image for c/state exists locally, building or
// pulling as needed, and returns what to run.
func (b *Builder) Resolve(ctx context.Context, c *contract.Contract, state string, opts Options) (*Resolved, error) {
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
		exists, err := b.Engine.ImageExists(ctx, ref)
		if err != nil {
			return nil, err
		}
		if !exists {
			if !opts.Pull {
				return nil, fmt.Errorf("%s/%s: image %s is not present and pulling is disabled", c.ID(), state, ref)
			}
			if err := b.Engine.ImagePull(ctx, ref, opts.Output); err != nil {
				return nil, err
			}
			res.Pulled = true
		}
		return res, nil
	}

	tag := c.ImageTag(state)
	res.Ref = tag
	if !opts.Force {
		exists, err := b.Engine.ImageExists(ctx, tag)
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
	tarStream io.Reader, opts Options) error {
	return b.Engine.ImageBuild(ctx, engine.BuildOptions{
		Context:    tarStream,
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		BuildArgs:  c.Base.BuildArgs,
		NoCache:    opts.NoCache,
		Labels:     b.labels(c, st, kind),
		Platform:   opts.Platform,
	}, opts.Output)
}

// -- overlay ------------------------------------------------------------------

func (b *Builder) buildOverlay(ctx context.Context, c *contract.Contract, st *contract.State, tag string, opts Options) error {
	baseRef := st.EffectiveImage(c.Base)
	if baseRef == "" {
		return errors.New("overlay needs an image base")
	}
	if opts.Pull {
		exists, err := b.Engine.ImageExists(ctx, baseRef)
		if err != nil {
			return err
		}
		if !exists {
			if err := b.Engine.ImagePull(ctx, baseRef, opts.Output); err != nil {
				return err
			}
		}
	}
	mc := newMemContext()
	var entries []overlayEntry
	for i, o := range st.Overlay {
		data, err := os.ReadFile(filepath.Join(c.Folder, filepath.FromSlash(o.Src)))
		if err != nil {
			return fmt.Errorf("overlay %s: %w", o.Src, err)
		}
		local := fmt.Sprintf("overlay_%d_%s", i, filepath.Base(o.Dest))
		mc.add(local, data, 0o644)
		entries = append(entries, overlayEntry{local: local, dest: o.Dest, mode: o.Mode})
	}
	mc.add("Dockerfile", []byte(overlayDockerfile(baseRef, entries, st.Environment)), 0o644)
	return b.build(ctx, c, st, contract.BuildKindOverlay, tag, "Dockerfile", mc.tar(), opts)
}

// -- local build (simulations, devices) ---------------------------------------

func (b *Builder) buildLocal(ctx context.Context, c *contract.Contract, st *contract.State, tag string, opts Options) error {
	ctxDir := filepath.Join(c.Folder, filepath.FromSlash(c.Base.Context))
	if info, err := os.Stat(ctxDir); err != nil || !info.IsDir() {
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
		if err := b.applyPatch(ctx, src, filepath.Join(c.Folder, filepath.FromSlash(st.Patch))); err != nil {
			return err
		}
	}
	mc := newMemContext()
	if err := mc.addTree(src, ""); err != nil {
		return err
	}
	for _, o := range st.Overlay {
		data, err := os.ReadFile(filepath.Join(c.Folder, filepath.FromSlash(o.Src)))
		if err != nil {
			return fmt.Errorf("overlay %s: %w", o.Src, err)
		}
		mc.add(strings.TrimPrefix(o.Dest, "/"), data, modeOf(o.Mode))
	}
	dockerfile := c.Base.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if err := bakeEnv(mc, dockerfile, st.Environment); err != nil {
		return err
	}
	return b.build(ctx, c, st, contract.BuildKindBuild, tag, dockerfile, mc.tar(), opts)
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
	repo := filepath.Join(tmp, "src")
	if out, err := b.git(ctx, "", 10*time.Minute, "clone", "--filter=blob:none", "--no-checkout", c.Base.Repo, repo); err != nil {
		return fmt.Errorf("clone %s: %s", c.Base.Repo, tail(out))
	}
	if out, err := b.git(ctx, repo, 2*time.Minute, "checkout", "--quiet", c.Base.Commit); err != nil {
		return fmt.Errorf("checkout %s: %s", c.Base.Commit, tail(out))
	}
	if st.Patch != "" {
		if err := b.applyPatch(ctx, repo, filepath.Join(c.Folder, filepath.FromSlash(st.Patch))); err != nil {
			return err
		}
	}
	mc := newMemContext()
	if err := mc.addTree(repo, ""); err != nil {
		return err
	}
	for _, o := range st.Overlay {
		data, err := os.ReadFile(filepath.Join(c.Folder, filepath.FromSlash(o.Src)))
		if err != nil {
			return fmt.Errorf("overlay %s: %w", o.Src, err)
		}
		mc.add(strings.TrimPrefix(o.Dest, "/"), data, modeOf(o.Mode))
	}
	dockerfile := c.Base.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	if err := bakeEnv(mc, dockerfile, st.Environment); err != nil {
		return err
	}
	return b.build(ctx, c, st, contract.BuildKindSource, tag, dockerfile, mc.tar(), opts)
}

// bakeEnv appends the state's environment to the Dockerfile so the published
// image is self-contained (the runner passes it at run time as well).
func bakeEnv(mc *memContext, dockerfile string, env map[string]string) error {
	if len(env) == 0 {
		return nil
	}
	f, ok := mc.files[filepath.ToSlash(dockerfile)]
	if !ok {
		return fmt.Errorf("build context has no %s", dockerfile)
	}
	extra := overlayDockerfile("", nil, env)
	extra = strings.TrimPrefix(extra, "FROM \n")
	data := append([]byte{}, f.data...)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(extra)...)
	mc.add(dockerfile, data, f.mode)
	return nil
}

func (b *Builder) applyPatch(ctx context.Context, dir, patch string) error {
	if out, err := b.git(ctx, dir, 2*time.Minute, "apply", "--unsafe-paths", "--directory", dir, patch); err == nil {
		return nil
	} else if _, perr := exec.LookPath("patch"); perr != nil {
		return fmt.Errorf("apply %s: %s", filepath.Base(patch), tail(out))
	}
	cmd := exec.CommandContext(ctx, "patch", "-p1", "-d", dir, "-i", patch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply %s: %s", filepath.Base(patch), tail(string(out)))
	}
	return nil
}

func (b *Builder) git(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
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
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return "..." + s[len(s)-300:]
	}
	return s
}

func modeOf(mode string) int64 {
	if mode == "" {
		return 0o644
	}
	var m int64
	fmt.Sscanf(mode, "%o", &m)
	if m == 0 {
		return 0o644
	}
	return m
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

// -- many at once ---------------------------------------------------------------

// Job is one (contract, state) to resolve.
type Job struct {
	Contract *contract.Contract
	State    string
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
