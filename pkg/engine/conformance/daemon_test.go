package conformance

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/distribution/reference"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// stubAPIVersion is what the stub advertises. It is recent enough for the SDK
// to use per-platform image inspects (1.49+); the built-in client caps it at
// its own MaxAPIVersion.
const stubAPIVersion = "1.51"

// daemon is an in-memory Docker Engine API stub: just the endpoints and the
// semantics the conformance cases need, modelled on dockerd's responses
// (status codes, JSON error bodies, progress streams, hijacked exec attach).
type daemon struct {
	srv *httptest.Server

	mu         sync.Mutex
	images     map[string]*stubImage // ref -> image
	containers map[string]*stubContainer
	networks   map[string]*stubNetwork // name -> network
	execs      map[string]*stubExec
	next       int
	nextPort   int
	faults     []*fault

	builds   []buildRecord
	buildErr string            // every build fails with this when set
	pullErr  map[string]string // ref -> error reported in the pull stream
	pushErr  map[string]string // ref -> error reported in the push stream
	// errForm is how stream errors are reported: "" for both the "error"
	// string and the "errorDetail" object (as dockerd does), or only one of
	// "error" / "errorDetail" (as other compatible daemons and proxies may).
	errForm string
	waitErr map[string]string // container name -> wait Error.Message
	logs    string
	execFn  func(container string, cmd []string) (int, string)
}

type stubImage struct {
	id, os, arch, variant string
}

type stubContainer struct {
	id, name, image string
	labels          map[string]string
	entrypoint, cmd []string
	// securityOpt, capAdd and capDrop are the HostConfig fields of the same
	// names, as the client sent them.
	securityOpt, capAdd, capDrop []string
	ports                        []stubPort
	networks                     map[string]*stubEndpoint // network name -> endpoint
	started                      bool
	running                      bool
	paused                       bool
	exitCode                     int
	files                        map[string]stubFile // absolute clean path -> file
}

// stubFile is a file in a stub container's filesystem: a regular file, a
// directory (fs.ModeDir) or a symlink (fs.ModeSymlink, data its target).
type stubFile struct {
	mode fs.FileMode
	data string
}

type stubPort struct {
	key      string // "80/tcp"
	hostIP   string
	hostPort string
}

type stubEndpoint struct {
	ip      string
	aliases []string
}

type stubNetwork struct {
	id       string
	spec     engine.NetworkSpec
	labels   map[string]string
	hostNext int
}

type stubExec struct {
	id, container string
	cmd           []string
	done          bool
	code          int
}

// buildRecord is what a build asked for, whichever engine sent it.
type buildRecord struct {
	Tags       []string
	Dockerfile string
	BuildArgs  map[string]string
	Labels     map[string]string
	NoCache    bool
	Platform   string
	Files      map[string]string
	// Query is the raw /build query (real engines only).
	Query url.Values
}

// fault makes requests matching method and path (versionless, a regexp)
// fail with status and message. With once it fires a single time.
type fault struct {
	method string
	path   *regexp.Regexp
	query  string // when set, the raw query must contain it
	status int
	msg    string
	once   bool
	fired  bool
	then   func(d *daemon) // runs (under d.mu) when the fault fires
}

func newDaemon(t *testing.T) *daemon {
	t.Helper()
	d := &daemon{
		images:     map[string]*stubImage{},
		containers: map[string]*stubContainer{},
		networks:   map[string]*stubNetwork{},
		execs:      map[string]*stubExec{},
		pullErr:    map[string]string{},
		pushErr:    map[string]string{},
		waitErr:    map[string]string{},
		nextPort:   49152,
	}
	// dockerd always has the predefined networks.
	for _, n := range []string{"bridge", "host", "none"} {
		d.networks[n] = &stubNetwork{id: d.newID(), spec: engine.NetworkSpec{Name: n, Driver: n}}
	}
	d.networks["bridge"].spec.Driver = "bridge"
	d.srv = httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.srv.Close)
	return d
}

// host is the DOCKER_HOST-style address of the stub.
func (d *daemon) host() string { return "tcp://" + d.srv.Listener.Addr().String() }

func (d *daemon) newID() string {
	d.next++
	return fmt.Sprintf("%064x", d.next)
}

// addImage stores ref for platform ("" = linux/amd64).
func (d *daemon) addImage(ref, platform string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.putImage(ref, platform)
}

func (d *daemon) putImage(ref, platform string) {
	if platform == "" {
		platform = "linux/amd64"
	}
	os, arch, variant := engine.SplitPlatform(platform)
	d.images[imageKey(ref)] = &stubImage{id: "sha256:" + d.newID(), os: os, arch: arch, variant: variant}
}

// imageKey is the name dockerd resolves an image reference to, so that
// "busybox", "busybox:latest" and "docker.io/library/busybox:latest" are one
// image. d.images is keyed by it.
func imageKey(ref string) string {
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return ref
	}
	return reference.TagNameOnly(named).String()
}

// familiar is how dockerd lists an image key ("busybox:latest").
func familiar(key string) string {
	named, err := reference.ParseNormalizedNamed(key)
	if err != nil {
		return key
	}
	return reference.FamiliarString(named)
}

// lookupImage returns the image ref names. Called with d.mu held.
func (d *daemon) lookupImage(ref string) (*stubImage, bool) {
	img, ok := d.images[imageKey(ref)]
	return img, ok
}

func (d *daemon) addNetwork(spec engine.NetworkSpec) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.putNetwork(spec, nil).id
}

func (d *daemon) putNetwork(spec engine.NetworkSpec, labels map[string]string) *stubNetwork {
	if spec.Driver == "" {
		spec.Driver = "bridge"
	}
	n := &stubNetwork{id: d.newID(), spec: spec, labels: labels}
	d.networks[spec.Name] = n
	return n
}

func (d *daemon) network(name string) (engine.NetworkSpec, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, ok := d.networks[name]
	if !ok {
		return engine.NetworkSpec{}, "", false
	}
	return n.spec, n.id, true
}

func (d *daemon) exit(idOrName string, code int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.container(idOrName); c != nil {
		c.running, c.paused, c.exitCode = false, false, code
	}
}

// writeFile puts a file in a container's filesystem (see stubFile).
func (d *daemon) writeFile(idOrName, p string, mode fs.FileMode, data string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c := d.container(idOrName); c != nil {
		if c.files == nil {
			c.files = map[string]stubFile{}
		}
		c.files[path.Clean(p)] = stubFile{mode: mode, data: data}
	}
}

// fail installs a fault.
func (d *daemon) fail(f *fault) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.faults = append(d.faults, f)
}

func (d *daemon) lastBuild() (buildRecord, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.builds) == 0 {
		return buildRecord{}, false
	}
	return d.builds[len(d.builds)-1], true
}

func (d *daemon) container(idOrName string) *stubContainer {
	idOrName = strings.TrimPrefix(idOrName, "/")
	for _, c := range d.containers {
		if c.id == idOrName || c.name == idOrName {
			return c
		}
	}
	return nil
}

var versionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, format string, a ...any) {
	writeJSON(w, status, map[string]string{"message": fmt.Sprintf(format, a...)})
}

// stream writes newline-delimited JSON progress messages.
func stream(w http.ResponseWriter, msgs ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for _, m := range msgs {
		_ = enc.Encode(m)
	}
}

// streamError is a progress-stream failure in form (see daemon.errForm).
func streamError(form, msg string) map[string]any {
	switch form {
	case "error":
		return map[string]any{"error": msg}
	case "errorDetail":
		return map[string]any{"errorDetail": map[string]string{"message": msg}}
	}
	return map[string]any{"errorDetail": map[string]string{"message": msg}, "error": msg}
}

func (d *daemon) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("API-Version", stubAPIVersion)
	w.Header().Set("OSType", "linux")
	path := versionPrefix.ReplaceAllString(r.URL.Path, "")

	d.mu.Lock()
	for _, f := range d.faults {
		if (f.once && f.fired) || (f.method != "" && f.method != r.Method) || !f.path.MatchString(path) ||
			(f.query != "" && !strings.Contains(r.URL.RawQuery, f.query)) {
			continue
		}
		f.fired = true
		if f.then != nil {
			f.then(d)
		}
		d.mu.Unlock()
		apiError(w, f.status, "%s", f.msg)
		return
	}
	d.mu.Unlock()

	switch {
	case path == "/_ping":
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "OK")
	case path == "/version":
		writeJSON(w, 200, map[string]string{"Version": "27.5.1", "ApiVersion": stubAPIVersion, "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64"})
	case path == "/images/json" && r.Method == http.MethodGet:
		d.imageList(w)
	case path == "/images/create" && r.Method == http.MethodPost:
		d.imagePull(w, r)
	case path == "/build" && r.Method == http.MethodPost:
		d.imageBuild(w, r)
	case strings.HasPrefix(path, "/images/"):
		d.images_(w, r, strings.TrimPrefix(path, "/images/"))
	case path == "/containers/json" && r.Method == http.MethodGet:
		d.containerList(w, r)
	case path == "/containers/create" && r.Method == http.MethodPost:
		d.containerCreate(w, r)
	case strings.HasPrefix(path, "/containers/"):
		d.containers_(w, r, strings.TrimPrefix(path, "/containers/"))
	case strings.HasPrefix(path, "/exec/"):
		d.exec(w, r, strings.TrimPrefix(path, "/exec/"))
	case path == "/networks/create" && r.Method == http.MethodPost:
		d.networkCreate(w, r)
	case strings.HasPrefix(path, "/networks/"):
		d.networks_(w, r, strings.TrimPrefix(path, "/networks/"))
	default:
		apiError(w, http.StatusNotFound, "page not found: %s %s", r.Method, path)
	}
}

// -- images -------------------------------------------------------------------

func (d *daemon) images_(w http.ResponseWriter, r *http.Request, rest string) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(rest, "/json"):
		d.imageInspect(w, r, strings.TrimSuffix(rest, "/json"))
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/tag"):
		d.imageTag(w, r, strings.TrimSuffix(rest, "/tag"))
	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/push"):
		d.imagePush(w, r, strings.TrimSuffix(rest, "/push"))
	case r.Method == http.MethodDelete:
		d.imageRemove(w, r, rest)
	default:
		apiError(w, http.StatusNotFound, "page not found")
	}
}

func (d *daemon) imageInspect(w http.ResponseWriter, r *http.Request, ref string) {
	d.mu.Lock()
	img, ok := d.lookupImage(ref)
	d.mu.Unlock()
	if !ok {
		apiError(w, http.StatusNotFound, "No such image: %s", ref)
		return
	}
	if p := r.URL.Query().Get("platform"); p != "" {
		// A per-platform inspect (API 1.49+): this store only holds the one
		// platform it was pulled or built for.
		var want struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		}
		if err := json.Unmarshal([]byte(p), &want); err != nil {
			apiError(w, http.StatusBadRequest, "invalid platform: %v", err)
			return
		}
		wp := want.OS + "/" + want.Architecture
		if want.Variant != "" {
			wp += "/" + want.Variant
		}
		if !engine.PlatformMatches(wp, img.os, img.arch, img.variant) {
			apiError(w, http.StatusNotFound, "image with reference %s was found but does not provide the specified platform (%s)", ref, wp)
			return
		}
	}
	writeJSON(w, 200, map[string]any{"Id": img.id, "RepoTags": []string{familiar(imageKey(ref))}, "Os": img.os, "Architecture": img.arch, "Variant": img.variant})
}

func (d *daemon) imageList(w http.ResponseWriter) {
	d.mu.Lock()
	byID := map[string][]string{}
	for key, img := range d.images {
		byID[img.id] = append(byID[img.id], familiar(key))
	}
	d.mu.Unlock()
	out := []map[string]any{}
	for id, refs := range byID {
		sort.Strings(refs)
		out = append(out, map[string]any{"Id": id, "RepoTags": refs, "Created": 0, "Size": 0, "Containers": -1})
	}
	// dockerd lists newest first, not by name: keep callers honest.
	sort.Slice(out, func(i, j int) bool { return out[i]["Id"].(string) > out[j]["Id"].(string) })
	writeJSON(w, 200, out)
}

func joinRef(repo, tag string) string {
	if tag == "" || strings.Contains(repo, "@") {
		return repo
	}
	return repo + ":" + tag
}

func (d *daemon) imagePull(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ref := joinRef(q.Get("fromImage"), q.Get("tag"))
	d.mu.Lock()
	msg, failing := d.pullErr[ref]
	form := d.errForm
	if !failing {
		d.putImage(ref, q.Get("platform"))
	}
	d.mu.Unlock()
	if failing {
		stream(w, map[string]string{"status": "Pulling from " + q.Get("fromImage")}, streamError(form, msg))
		return
	}
	stream(w,
		map[string]string{"status": "Pulling from " + q.Get("fromImage"), "id": q.Get("tag")},
		map[string]string{"status": "Downloading", "id": "aaaa", "progress": "[=>  ] 1B/2B"},
		map[string]string{"status": "Status: Downloaded newer image for " + ref},
	)
}

func (d *daemon) imageBuild(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rec := buildRecord{Tags: q["t"], Dockerfile: q.Get("dockerfile"), Platform: q.Get("platform"), Query: q, Files: map[string]string{}}
	rec.NoCache = q.Get("nocache") == "1" || q.Get("nocache") == "true"
	if s := q.Get("buildargs"); s != "" {
		var args map[string]*string
		_ = json.Unmarshal([]byte(s), &args)
		rec.BuildArgs = map[string]string{}
		for k, v := range args {
			if v != nil {
				rec.BuildArgs[k] = *v
			}
		}
	}
	if s := q.Get("labels"); s != "" {
		_ = json.Unmarshal([]byte(s), &rec.Labels)
	}
	tr := tar.NewReader(r.Body)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(tr)
		rec.Files[h.Name] = string(b)
	}
	d.mu.Lock()
	d.builds = append(d.builds, rec)
	if !hasDockerfile(rec.Files, rec.Dockerfile) {
		d.mu.Unlock()
		name := rec.Dockerfile
		if name == "" {
			name = "Dockerfile"
		}
		apiError(w, http.StatusInternalServerError, "Cannot locate specified Dockerfile: %s", name)
		return
	}
	failMsg, form := d.buildErr, d.errForm
	if failMsg == "" {
		for _, t := range rec.Tags {
			d.putImage(t, rec.Platform)
		}
	}
	d.mu.Unlock()
	if failMsg != "" {
		stream(w, map[string]string{"stream": "Step 1/2 : FROM scratch\n"}, map[string]string{"stream": " ---> Running in 0123456789ab\n"}, streamError(form, failMsg))
		return
	}
	stream(w, map[string]string{"stream": "Step 1/1 : FROM scratch\n"}, map[string]string{"stream": "Successfully tagged " + strings.Join(rec.Tags, ",") + "\n"})
}

// hasDockerfile reports whether a build context holds the Dockerfile asked
// for (name, "Dockerfile" when empty; the default also matches "dockerfile",
// as in dockerd).
func hasDockerfile(files map[string]string, name string) bool {
	clean := func(p string) string { return strings.TrimPrefix(path.Clean("/"+p), "/") }
	want := []string{clean(name)}
	if name == "" {
		want = []string{"Dockerfile", "dockerfile"}
	}
	for f := range files {
		for _, w := range want {
			if clean(f) == w {
				return true
			}
		}
	}
	return false
}

func (d *daemon) imageTag(w http.ResponseWriter, r *http.Request, source string) {
	q := r.URL.Query()
	tag := q.Get("tag")
	if tag == "" {
		tag = "latest"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	img, ok := d.lookupImage(source)
	if !ok {
		apiError(w, http.StatusNotFound, "No such image: %s", source)
		return
	}
	cp := *img
	d.images[imageKey(joinRef(q.Get("repo"), tag))] = &cp
	w.WriteHeader(http.StatusCreated)
}

func (d *daemon) imagePush(w http.ResponseWriter, r *http.Request, repo string) {
	ref := joinRef(repo, r.URL.Query().Get("tag"))
	d.mu.Lock()
	_, ok := d.lookupImage(ref)
	msg, failing := d.pushErr[ref]
	form := d.errForm
	d.mu.Unlock()
	if !ok {
		apiError(w, http.StatusNotFound, "An image does not exist locally with the tag: %s", repo)
		return
	}
	if failing {
		stream(w, map[string]string{"status": "The push refers to repository [" + repo + "]"}, streamError(form, msg))
		return
	}
	stream(w, map[string]string{"status": "The push refers to repository [" + repo + "]"})
}

func (d *daemon) imageRemove(w http.ResponseWriter, r *http.Request, ref string) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.lookupImage(ref); !ok {
		apiError(w, http.StatusNotFound, "No such image: %s", ref)
		return
	}
	if !force {
		for _, c := range d.containers {
			if imageKey(c.image) == imageKey(ref) {
				apiError(w, http.StatusConflict, "conflict: unable to remove repository reference %q (must force) - container %s is using its referenced image", ref, c.id[:12])
				return
			}
		}
	}
	delete(d.images, imageKey(ref))
	writeJSON(w, 200, []map[string]string{{"Untagged": ref}})
}

// -- containers -------------------------------------------------------------------

func (d *daemon) containerCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Image      string
		Entrypoint []string
		Cmd        []string
		Labels     map[string]string
		HostConfig struct {
			NetworkMode  string
			PortBindings map[string][]struct{ HostIp, HostPort string }
			SecurityOpt  []string
			CapAdd       []string
			CapDrop      []string
		}
		NetworkingConfig struct {
			EndpointsConfig map[string]struct {
				Aliases    []string
				IPAMConfig *struct{ IPv4Address string }
			}
		}
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	name := r.URL.Query().Get("name")
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.lookupImage(body.Image); !ok {
		apiError(w, http.StatusNotFound, "No such image: %s", body.Image)
		return
	}
	if name != "" && d.container(name) != nil {
		apiError(w, http.StatusConflict, "Conflict. The container name \"/%s\" is already in use by container \"%s\".", name, d.container(name).id)
		return
	}
	mode := body.HostConfig.NetworkMode
	if mode == "" || mode == "default" {
		mode = "bridge"
	}
	n, ok := d.networks[mode]
	if !ok {
		apiError(w, http.StatusNotFound, "network %s not found", mode)
		return
	}
	c := &stubContainer{id: d.newID(), name: name, image: body.Image, labels: body.Labels, entrypoint: body.Entrypoint, cmd: body.Cmd, networks: map[string]*stubEndpoint{},
		securityOpt: body.HostConfig.SecurityOpt, capAdd: body.HostConfig.CapAdd, capDrop: body.HostConfig.CapDrop}
	if c.name == "" {
		c.name = "auto_" + c.id[:6]
	}
	ep := &stubEndpoint{}
	if cfg, ok := body.NetworkingConfig.EndpointsConfig[mode]; ok {
		ep.aliases = cfg.Aliases
		if cfg.IPAMConfig != nil {
			ep.ip = cfg.IPAMConfig.IPv4Address
		}
	}
	if ep.ip == "" {
		ep.ip = d.allocIP(n)
	}
	c.networks[mode] = ep
	keys := make([]string, 0, len(body.HostConfig.PortBindings))
	for k := range body.HostConfig.PortBindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, b := range body.HostConfig.PortBindings[k] {
			c.ports = append(c.ports, stubPort{key: k, hostIP: b.HostIp, hostPort: b.HostPort})
		}
	}
	d.containers[c.id] = c
	writeJSON(w, http.StatusCreated, map[string]any{"Id": c.id, "Warnings": []string{}})
}

func (d *daemon) allocIP(n *stubNetwork) string {
	n.hostNext++
	return fmt.Sprintf("172.31.%d.%d", len(n.id)%200, n.hostNext+1)
}

func (d *daemon) containers_(w http.ResponseWriter, r *http.Request, rest string) {
	id, action, _ := strings.Cut(rest, "/")
	d.mu.Lock()
	c := d.container(id)
	d.mu.Unlock()
	if c == nil {
		apiError(w, http.StatusNotFound, "No such container: %s", id)
		return
	}
	switch {
	case action == "start" && r.Method == http.MethodPost:
		d.mu.Lock()
		if c.paused {
			d.mu.Unlock()
			apiError(w, http.StatusConflict, "cannot start a paused container, try unpause instead")
			return
		}
		if c.running {
			// dockerd: starting a running container is 304 Not Modified.
			d.mu.Unlock()
			w.WriteHeader(http.StatusNotModified)
			return
		}
		c.started, c.running = true, true
		for i := range c.ports {
			if c.ports[i].hostPort == "" || c.ports[i].hostPort == "0" {
				d.nextPort++
				c.ports[i].hostPort = strconv.Itoa(d.nextPort)
			}
		}
		d.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case action == "json" && r.Method == http.MethodGet:
		d.containerInspect(w, c)
	case action == "" && r.Method == http.MethodDelete:
		q := r.URL.Query()
		d.mu.Lock()
		defer d.mu.Unlock()
		if c.running && q.Get("force") != "1" && q.Get("force") != "true" {
			apiError(w, http.StatusConflict, "cannot remove container \"/%s\": container is running: stop the container before removing or force remove", c.name)
			return
		}
		delete(d.containers, c.id)
		w.WriteHeader(http.StatusNoContent)
	case action == "wait" && r.Method == http.MethodPost:
		d.containerWait(w, r, c)
	case action == "logs" && r.Method == http.MethodGet:
		d.mu.Lock()
		logs := d.logs
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		w.WriteHeader(200)
		_, _ = w.Write(frame(1, []byte(logs)))
	case action == "exec" && r.Method == http.MethodPost:
		var body struct{ Cmd []string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		d.mu.Lock()
		defer d.mu.Unlock()
		if !c.running {
			apiError(w, http.StatusConflict, "container %s is not running", c.id)
			return
		}
		if c.paused {
			apiError(w, http.StatusConflict, "Container %s is paused, unpause the container before exec", c.name)
			return
		}
		e := &stubExec{id: d.newID(), container: c.name, cmd: body.Cmd}
		d.execs[e.id] = e
		writeJSON(w, http.StatusCreated, map[string]string{"Id": e.id})
	case action == "pause" && r.Method == http.MethodPost:
		d.mu.Lock()
		defer d.mu.Unlock()
		switch {
		case !c.running:
			apiError(w, http.StatusConflict, "container %s is not running", c.id)
		case c.paused:
			apiError(w, http.StatusConflict, "container %s is already paused", c.id)
		default:
			c.paused = true
			w.WriteHeader(http.StatusNoContent)
		}
	case action == "unpause" && r.Method == http.MethodPost:
		d.mu.Lock()
		defer d.mu.Unlock()
		if !c.paused {
			// dockerd answers 500 here, not 409.
			apiError(w, http.StatusInternalServerError, "Container %s is not paused", c.id)
			return
		}
		c.paused = false
		w.WriteHeader(http.StatusNoContent)
	case action == "archive" && (r.Method == http.MethodHead || r.Method == http.MethodGet):
		d.archive(w, r, c)
	default:
		apiError(w, http.StatusNotFound, "page not found")
	}
}

// lstat returns the file at the clean path p: a written one, or a directory
// implied by one below it.
func (c *stubContainer) lstat(p string) (stubFile, bool) {
	if f, ok := c.files[p]; ok {
		return f, true
	}
	if p == "/" {
		return stubFile{mode: fs.ModeDir | 0o755}, true
	}
	for q := range c.files {
		if strings.HasPrefix(q, p+"/") {
			return stubFile{mode: fs.ModeDir | 0o755}, true
		}
	}
	return stubFile{}, false
}

// archive answers HEAD (stat) and GET (tar) /containers/{id}/archive like
// dockerd: the stat of path in the X-Docker-Container-Path-Stat header, and a
// tar whose entries are named after path's base name ("/" for the root).
func (d *daemon) archive(w http.ResponseWriter, r *http.Request, c *stubContainer) {
	p := r.URL.Query().Get("path")
	d.mu.Lock()
	defer d.mu.Unlock()
	f, ok := c.lstat(path.Clean(p))
	if !ok {
		apiError(w, http.StatusNotFound, "Could not find the file %s in container %s", p, c.name)
		return
	}
	p = path.Clean(p)
	root := path.Base(p)
	st, _ := json.Marshal(map[string]any{"name": root, "size": len(f.data), "mode": uint32(f.mode), "mtime": "2026-01-01T00:00:00Z", "linkTarget": ""})
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(st))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	under := strings.TrimSuffix(p, "/") + "/"
	entry := func(name string, f stubFile) {
		h := &tar.Header{Name: name, Mode: int64(f.mode.Perm())}
		switch {
		case f.mode.IsDir():
			h.Typeflag, h.Name = tar.TypeDir, strings.TrimSuffix(name, "/")+"/"
		case f.mode&fs.ModeSymlink != 0:
			h.Typeflag, h.Linkname = tar.TypeSymlink, f.data
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(f.data))
		}
		_ = tw.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			_, _ = io.WriteString(tw, f.data)
		}
	}
	entry(root, f)
	if f.mode.IsDir() {
		var names []string
		for q := range c.files {
			if strings.HasPrefix(q, under) {
				names = append(names, q)
			}
		}
		sort.Strings(names)
		for _, q := range names {
			entry(strings.TrimSuffix(root, "/")+"/"+strings.TrimPrefix(q, under), c.files[q])
		}
	}
	_ = tw.Close()
	w.Header().Set("Content-Type", "application/x-tar")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (d *daemon) containerInspect(w http.ResponseWriter, c *stubContainer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	status := "created"
	switch {
	case c.paused:
		status = "paused"
	case c.running:
		status = "running"
	case c.started:
		status = "exited"
	}
	nets := map[string]any{}
	for name, ep := range c.networks {
		nets[name] = map[string]any{"IPAddress": ep.ip, "IPPrefixLen": 16, "Aliases": ep.aliases, "NetworkID": d.networks[name].id}
	}
	// Like dockerd, a port has no binding until the container runs.
	ports := map[string]any{}
	for _, p := range c.ports {
		if !c.running {
			ports[p.key] = nil
			continue
		}
		ip := p.hostIP
		if ip == "" {
			ip = "0.0.0.0"
		}
		prev, _ := ports[p.key].([]map[string]string)
		ports[p.key] = append(prev, map[string]string{"HostIp": ip, "HostPort": p.hostPort})
	}
	writeJSON(w, 200, map[string]any{
		"Id":     c.id,
		"Name":   "/" + c.name,
		"Image":  d.images[imageKey(c.image)].idOr(c.image),
		"State":  map[string]any{"Status": status, "Running": c.running, "Paused": c.paused, "ExitCode": c.exitCode},
		"Config": map[string]any{"Image": c.image, "Labels": c.labels},
		"NetworkSettings": map[string]any{
			"Networks": nets,
			"Ports":    ports,
		},
	})
}

func (img *stubImage) idOr(fallback string) string {
	if img == nil {
		return fallback
	}
	return img.id
}

func (d *daemon) containerWait(w http.ResponseWriter, r *http.Request, c *stubContainer) {
	for {
		d.mu.Lock()
		running, code, gone := c.running, c.exitCode, d.containers[c.id] == nil
		msg, failing := d.waitErr[c.name]
		d.mu.Unlock()
		if !running || gone {
			resp := map[string]any{"StatusCode": code}
			if failing {
				resp["Error"] = map[string]string{"Message": msg}
			}
			writeJSON(w, 200, resp)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (d *daemon) containerList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	all := q.Get("all") == "1" || q.Get("all") == "true"
	var names []string
	if f := q.Get("filters"); f != "" {
		// The built-in client sends {"name":["x"]}, the SDK {"name":{"x":true}}.
		var asList map[string][]string
		var asSet map[string]map[string]bool
		if json.Unmarshal([]byte(f), &asList) == nil {
			names = asList["name"]
		} else if json.Unmarshal([]byte(f), &asSet) == nil {
			for n := range asSet["name"] {
				names = append(names, n)
			}
		} else {
			apiError(w, http.StatusBadRequest, "invalid filter %q", f)
			return
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []map[string]any{}
	for _, c := range d.containers {
		if !all && !c.running {
			continue
		}
		match := len(names) == 0
		for _, n := range names {
			// dockerd matches the name filter as a regexp against "/name".
			if re, err := regexp.Compile(n); err == nil && re.MatchString("/"+c.name) {
				match = true
			}
		}
		if !match {
			continue
		}
		state, status := "created", "Created"
		switch {
		case c.paused:
			state, status = "paused", "Up 2 seconds (Paused)"
		case c.running:
			state, status = "running", "Up 2 seconds"
		case c.started:
			state, status = "exited", fmt.Sprintf("Exited (%d) 1 second ago", c.exitCode)
		}
		out = append(out, map[string]any{"Id": c.id, "Names": []string{"/" + c.name}, "Image": c.image, "State": state, "Status": status, "Labels": c.labels})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["Id"].(string) > out[j]["Id"].(string) })
	writeJSON(w, 200, out)
}

// -- exec -------------------------------------------------------------------------

func frame(stream byte, p []byte) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
	return append(h, p...)
}

func (d *daemon) exec(w http.ResponseWriter, r *http.Request, rest string) {
	id, action, _ := strings.Cut(rest, "/")
	d.mu.Lock()
	e := d.execs[id]
	fn := d.execFn
	d.mu.Unlock()
	if e == nil {
		apiError(w, http.StatusNotFound, "No such exec instance: %s", id)
		return
	}
	switch {
	case action == "start" && r.Method == http.MethodPost:
		code, out := 0, ""
		if fn != nil {
			code, out = fn(e.container, e.cmd)
		}
		d.mu.Lock()
		e.done, e.code = true, code
		d.mu.Unlock()
		if strings.EqualFold(r.Header.Get("Upgrade"), "tcp") {
			// The SDK attaches with a hijacked, upgraded connection.
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(rw, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_, _ = rw.Write(frame(1, []byte(out)))
			_ = rw.Flush()
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
		w.WriteHeader(200)
		_, _ = w.Write(frame(1, []byte(out)))
	case action == "json" && r.Method == http.MethodGet:
		d.mu.Lock()
		defer d.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ID": e.id, "Running": !e.done, "ExitCode": e.code})
	default:
		apiError(w, http.StatusNotFound, "page not found")
	}
}

// -- networks -------------------------------------------------------------------

func (d *daemon) networkByNameOrID(s string) *stubNetwork {
	if n, ok := d.networks[s]; ok {
		return n
	}
	for _, n := range d.networks {
		if n.id == s {
			return n
		}
	}
	return nil
}

func (d *daemon) networkCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string
		Driver   string
		Internal bool
		Options  map[string]string
		Labels   map[string]string
		IPAM     *struct {
			Config []struct{ Subnet, Gateway string }
		}
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.networks[body.Name]; ok {
		apiError(w, http.StatusConflict, "network with name %s already exists", body.Name)
		return
	}
	spec := engine.NetworkSpec{Name: body.Name, Driver: body.Driver, Internal: body.Internal, Options: body.Options}
	if body.IPAM != nil && len(body.IPAM.Config) > 0 {
		spec.Subnet, spec.Gateway = body.IPAM.Config[0].Subnet, body.IPAM.Config[0].Gateway
	}
	n := d.putNetwork(spec, body.Labels)
	writeJSON(w, http.StatusCreated, map[string]string{"Id": n.id, "Warning": ""})
}

func (d *daemon) networks_(w http.ResponseWriter, r *http.Request, rest string) {
	name, action, _ := strings.Cut(rest, "/")
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.networkByNameOrID(name)
	if n == nil {
		apiError(w, http.StatusNotFound, "network %s not found", name)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		ipam := map[string]any{"Driver": "default", "Config": []map[string]string{}}
		if n.spec.Subnet != "" {
			ipam["Config"] = []map[string]string{{"Subnet": n.spec.Subnet, "Gateway": n.spec.Gateway}}
		}
		writeJSON(w, 200, map[string]any{"Name": n.spec.Name, "Id": n.id, "Driver": n.spec.Driver, "Internal": n.spec.Internal,
			"Options": n.spec.Options, "Labels": n.labels, "IPAM": ipam, "Scope": "local"})
	case action == "" && r.Method == http.MethodDelete:
		for _, c := range d.containers {
			if _, ok := c.networks[n.spec.Name]; ok {
				apiError(w, http.StatusForbidden, "error while removing network: network %s id %s has active endpoints", n.spec.Name, n.id)
				return
			}
		}
		delete(d.networks, n.spec.Name)
		w.WriteHeader(http.StatusNoContent)
	case action == "connect" && r.Method == http.MethodPost:
		var body struct {
			Container      string
			EndpointConfig *struct{ Aliases []string }
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			apiError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}
		c := d.container(body.Container)
		if c == nil {
			apiError(w, http.StatusNotFound, "No such container: %s", body.Container)
			return
		}
		if _, ok := c.networks[n.spec.Name]; ok {
			apiError(w, http.StatusForbidden, "endpoint with name %s already exists in network %s", c.name, n.spec.Name)
			return
		}
		ep := &stubEndpoint{ip: d.allocIP(n)}
		if body.EndpointConfig != nil {
			ep.aliases = body.EndpointConfig.Aliases
		}
		c.networks[n.spec.Name] = ep
		w.WriteHeader(http.StatusOK)
	default:
		apiError(w, http.StatusNotFound, "page not found")
	}
}
