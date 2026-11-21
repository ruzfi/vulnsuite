package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ruzfi/vulnsuite/pkg/engine"
	"github.com/ruzfi/vulnsuite/pkg/engine/registryauth"
)

// ImageExists reports whether ref is present locally (for platform, when set).
// This client speaks API 1.41, which cannot inspect a non-default platform of
// a multi-platform store, so an image whose default variant is another
// platform counts as missing and is pulled (a no-op download when present).
func (c *Client) ImageExists(ctx context.Context, ref, platform string) (bool, error) {
	var img struct {
		Os           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Variant      string `json:"Variant"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(ref)+"/json", nil, nil, &img)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return engine.PlatformMatches(platform, img.Os, img.Architecture, img.Variant), nil
}

// ImagePlatform implements engine.ImagePlatformer.
func (c *Client) ImagePlatform(ctx context.Context, ref string) (string, error) {
	var img struct {
		Os           string `json:"Os"`
		Architecture string `json:"Architecture"`
		Variant      string `json:"Variant"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(ref)+"/json", nil, nil, &img); err != nil {
		return "", err
	}
	return engine.JoinPlatform(img.Os, img.Architecture, img.Variant), nil
}

var _ engine.ImagePlatformer = (*Client)(nil)

// splitRef splits "repo:tag", "repo@sha256:..." or "repo" into (fromImage, tag)
// as the /images/create endpoint wants them.
func splitRef(ref string) (string, string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref, "" // repo@digest is passed whole
	}
	// the last ':' after the last '/' is the tag separator
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, "latest"
}

// ImagePull pulls ref for platform (empty = daemon default), streaming progress to out.
func (c *Client) ImagePull(ctx context.Context, ref, platform string, out io.Writer) error {
	from, tag := splitRef(ref)
	q := url.Values{"fromImage": {from}}
	if tag != "" {
		q.Set("tag", tag)
	}
	if platform != "" {
		q.Set("platform", platform)
	}
	headers := map[string]string{}
	if auth := registryauth.ForContext(ctx, ref); auth != "" {
		headers["X-Registry-Auth"] = auth
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, nil, headers)
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer resp.Body.Close()
	if err := drainStream(resp.Body, out); err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	return nil
}

// ImageBuild builds an image from a tar context.
func (c *Client) ImageBuild(ctx context.Context, opts engine.BuildOptions, out io.Writer) error {
	q := url.Values{}
	for _, t := range opts.Tags {
		q.Add("t", t)
	}
	if opts.Dockerfile != "" {
		q.Set("dockerfile", opts.Dockerfile)
	}
	if len(opts.BuildArgs) > 0 {
		b, _ := json.Marshal(opts.BuildArgs)
		q.Set("buildargs", string(b))
	}
	if len(opts.Labels) > 0 {
		b, _ := json.Marshal(opts.Labels)
		q.Set("labels", string(b))
	}
	if opts.NoCache {
		q.Set("nocache", "1")
	}
	if opts.Pull {
		q.Set("pull", "1")
	}
	if opts.Platform != "" {
		q.Set("platform", opts.Platform)
	}
	// Remove intermediate containers, also when a step fails (forcerm), as
	// the SDK engine does with ForceRemove; otherwise every failed RUN step
	// of the legacy builder leaves a stopped container behind.
	q.Set("rm", "1")
	q.Set("forcerm", "1")
	headers := map[string]string{"Content-Type": "application/x-tar"}
	if cfg := registryauth.ConfigsHeaderContext(ctx); cfg != "" {
		headers["X-Registry-Config"] = cfg
	}
	resp, err := c.do(ctx, http.MethodPost, "/build", q, opts.Context, headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return drainStream(resp.Body, out)
}

// ImageTag tags source as target.
func (c *Client) ImageTag(ctx context.Context, source, target string) error {
	repo, tag := splitRef(target)
	q := url.Values{"repo": {repo}}
	if tag != "" {
		q.Set("tag", tag)
	}
	return c.doJSON(ctx, http.MethodPost, "/images/"+url.PathEscape(source)+"/tag", q, nil, nil)
}

// ImagePush pushes ref, streaming progress to out.
func (c *Client) ImagePush(ctx context.Context, ref string, out io.Writer) error {
	repo, tag := splitRef(ref)
	q := url.Values{}
	if tag != "" {
		q.Set("tag", tag)
	}
	auth := registryauth.ForPushContext(ctx, ref)
	if auth == "" {
		auth = registryauth.Empty()
	}
	resp, err := c.do(ctx, http.MethodPost, "/images/"+url.PathEscape(repo)+"/push", q, nil,
		map[string]string{"X-Registry-Auth": auth})
	if err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	defer resp.Body.Close()
	if err := drainStream(resp.Body, out); err != nil {
		return fmt.Errorf("push %s: %w", ref, err)
	}
	return nil
}

// ImageRemove deletes an image.
func (c *Client) ImageRemove(ctx context.Context, ref string, force bool) error {
	q := url.Values{}
	if force {
		q.Set("force", "1")
	}
	err := c.doJSON(ctx, http.MethodDelete, "/images/"+url.PathEscape(ref), q, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// ImageList lists repo:tag references whose repository starts with repoPrefix.
func (c *Client) ImageList(ctx context.Context, repoPrefix string) ([]string, error) {
	var imgs []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/json", nil, nil, &imgs); err != nil {
		return nil, err
	}
	var out []string
	for _, im := range imgs {
		for _, t := range im.RepoTags {
			if strings.HasPrefix(t, repoPrefix) {
				out = append(out, t)
			}
		}
	}
	return out, nil
}
