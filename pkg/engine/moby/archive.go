package moby

import (
	"context"
	"fmt"
	"io/fs"
	"path"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// ContainerPause freezes a running container.
func (e *Engine) ContainerPause(ctx context.Context, id string) error {
	_, err := e.cli.ContainerPause(ctx, id, client.ContainerPauseOptions{})
	return err
}

// ContainerUnpause thaws a paused container.
func (e *Engine) ContainerUnpause(ctx context.Context, id string) error {
	_, err := e.cli.ContainerUnpause(ctx, id, client.ContainerUnpauseOptions{})
	return err
}

// cleanPath checks that p is absolute and cleans it, so a trailing "/" or
// "/." cannot make the daemon follow a final symlink or change how it names
// the archive's entries.
func cleanPath(p string) (string, error) {
	if !path.IsAbs(p) {
		return "", fmt.Errorf("container path %q is not absolute", p)
	}
	return path.Clean(p), nil
}

// archiveErr resolves an archive API not-found into a missing container (the
// daemon's error) or a missing path (fs.ErrNotExist): a HEAD answer has no
// body to tell them apart.
func (e *Engine) archiveErr(ctx context.Context, id, p string, err error) error {
	if !cerrdefs.IsNotFound(err) {
		return err
	}
	if _, ierr := e.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{}); ierr != nil {
		return ierr
	}
	return fmt.Errorf("%s in container %s: %w", p, id, fs.ErrNotExist)
}

// ContainerStatPath returns the mode of p in the container.
func (e *Engine) ContainerStatPath(ctx context.Context, id, p string) (fs.FileMode, error) {
	p, err := cleanPath(p)
	if err != nil {
		return 0, err
	}
	res, err := e.cli.ContainerStatPath(ctx, id, client.ContainerStatPathOptions{Path: p})
	if err != nil {
		return 0, e.archiveErr(ctx, id, p, err)
	}
	return res.Stat.Mode, nil
}

// ContainerReadDir returns the regular files directly in dir, each cut to
// maxBytes.
func (e *Engine) ContainerReadDir(ctx context.Context, id, dir string, maxBytes int64) (map[string]engine.FileContent, error) {
	dir, err := cleanPath(dir)
	if err != nil {
		return nil, err
	}
	res, err := e.cli.CopyFromContainer(ctx, id, client.CopyFromContainerOptions{SourcePath: dir})
	if err != nil {
		return nil, e.archiveErr(ctx, id, dir, err)
	}
	defer res.Content.Close()
	if !res.Stat.Mode.IsDir() {
		return nil, fmt.Errorf("%s in container %s is not a directory (mode %s)", dir, id, res.Stat.Mode)
	}
	return engine.DirFilesFromTar(res.Content, res.Stat.Name, maxBytes)
}

var (
	_ engine.Pauser     = (*Engine)(nil)
	_ engine.FileReader = (*Engine)(nil)
)
