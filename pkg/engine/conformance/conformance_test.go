package conformance

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ruzfi/vulnsuite/pkg/engine"
)

// Pull requests that fix a divergence this suite pins down. Remove the skip
// that names one once it has merged.
const (
	pr73 = "fixed by #73 (built-in ContainerWait error, built-in forcerm, SDK ImageExists errors)"
	pr81 = "fixed by #81 (the fake's NetworkEnsure keeps an existing network)"
)

const (
	img     = "registry.example/vs/app:1"
	imgB    = "registry.example/vs/other:2"
	foreign = "registry.example/elsewhere/x:1"
)

type conformanceCase struct {
	name string
	run  func(t *testing.T, h *harness)
}

func TestConformance(t *testing.T) {
	// The real clients must reach the stub and nothing else.
	for _, k := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
		t.Setenv(k, "")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, b := range backends {
				t.Run(b.name, func(t *testing.T) {
					c.run(t, b.new(t))
				})
			}
		})
	}
}

// bg is a context for one call, bounded so a hung stub fails the test instead
// of the run.
func bg(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func tarOf(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n]))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(files[n]))
	}
	tw.Close()
	return &buf
}

func mustExist(t *testing.T, h *harness, ref, platform string, want bool) {
	t.Helper()
	got, err := h.eng.ImageExists(bg(t), ref, platform)
	if err != nil || got != want {
		t.Fatalf("ImageExists(%s, %q) = %v, %v; want %v, nil", ref, platform, got, err, want)
	}
}

// create makes a container from img on network (created first when missing).
func create(t *testing.T, h *harness, spec engine.ContainerSpec) string {
	t.Helper()
	if spec.Image == "" {
		spec.Image = img
	}
	if ok, _ := h.eng.ImageExists(bg(t), spec.Image, ""); !ok {
		h.seedImage(spec.Image, "")
	}
	if spec.Network != nil {
		if ok, _ := h.eng.NetworkExists(bg(t), spec.Network.Name); !ok {
			h.seedNetwork(engine.NetworkSpec{Name: spec.Network.Name})
		}
	}
	id, err := h.eng.ContainerCreate(bg(t), spec)
	if err != nil || id == "" {
		t.Fatalf("ContainerCreate(%s) = %q, %v", spec.Name, id, err)
	}
	return id
}

func run(t *testing.T, h *harness, spec engine.ContainerSpec) string {
	t.Helper()
	id := create(t, h, spec)
	if err := h.eng.ContainerStart(bg(t), id); err != nil {
		t.Fatalf("ContainerStart(%s): %v", spec.Name, err)
	}
	return id
}

var cases = []conformanceCase{
	// -- daemon ------------------------------------------------------------------
	{"ping_and_info", func(t *testing.T, h *harness) {
		v, err := h.eng.Ping(bg(t))
		if err != nil || v == "" {
			t.Fatalf("Ping = %q, %v", v, err)
		}
		info, err := h.eng.Info(bg(t))
		if err != nil || info != (engine.HostInfo{OS: "linux", Arch: "amd64"}) {
			t.Fatalf("Info = %+v, %v; want linux/amd64", info, err)
		}
	}},
	{"ping_daemon_error_is_error", func(t *testing.T, h *harness) {
		h.fail(t, "GET", `^/version$`, 500, "daemon is shutting down")
		if _, err := h.eng.Ping(bg(t)); !contains(err, "daemon is shutting down") {
			t.Fatalf("Ping error = %v, want the daemon's message", err)
		}
	}},

	// -- ImageExists: false only for not-found -------------------------------------
	{"image_exists_present_and_missing", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		mustExist(t, h, img, "", true)
		mustExist(t, h, imgB, "", false)
	}},
	{"image_exists_platform", func(t *testing.T, h *harness) {
		h.seedImage(img, "linux/amd64")
		mustExist(t, h, img, "linux/amd64", true)
		mustExist(t, h, img, "linux/x86_64", true)
		mustExist(t, h, img, "linux/arm64", false)
	}},
	{"image_exists_daemon_error_is_error", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		h.fail(t, "GET", `^/images/.+/json$`, 500, "layer store corrupt")
		if ok, err := h.eng.ImageExists(bg(t), img, ""); err == nil {
			t.Fatalf("ImageExists = %v, nil; a daemon 500 must be an error, not a missing image", ok)
		}
	}},
	{"image_exists_platform_inspect_error_is_error", func(t *testing.T, h *harness) {
		h.divergence(t, map[string]string{
			sdk: pr73,
			api: "not applicable: the built-in client speaks API <= 1.47 and never inspects per platform",
		})
		h.seedImage(img, "linux/amd64")
		f := h.fail(t, "GET", `^/images/.+/json$`, 500, "containerd unavailable")
		f.query = "platform="
		if ok, err := h.eng.ImageExists(bg(t), img, "linux/arm64"); err == nil {
			t.Fatalf("ImageExists = %v, nil; a failed per-platform inspect must be an error", ok)
		}
	}},
	{"image_exists_cancelled_context_is_error", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		for _, ref := range []string{img, imgB} {
			if ok, err := h.eng.ImageExists(cancelled(), ref, ""); err == nil {
				t.Fatalf("ImageExists(%s) with a cancelled context = %v, nil; want an error", ref, ok)
			}
		}
	}},

	// -- pull / build / tag / push / remove / list ----------------------------------
	{"image_pull", func(t *testing.T, h *harness) {
		var out bytes.Buffer
		if err := h.eng.ImagePull(bg(t), img, "linux/arm64", &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() == 0 {
			t.Error("ImagePull wrote no progress to out")
		}
		mustExist(t, h, img, "linux/arm64", true)
		if err := h.eng.ImagePull(bg(t), imgB, "", nil); err != nil {
			t.Fatalf("ImagePull with a nil writer: %v", err)
		}
		mustExist(t, h, imgB, "", true)
	}},
	{"image_pull_stream_error", func(t *testing.T, h *harness) {
		h.failPull(img, "manifest unknown")
		err := h.eng.ImagePull(bg(t), img, "", nil)
		if !contains(err, "manifest unknown") {
			t.Fatalf("ImagePull error = %v, want the registry's message", err)
		}
		mustExist(t, h, img, "", false)
	}},
	{"image_pull_http_error", func(t *testing.T, h *harness) {
		h.fail(t, "POST", `^/images/create$`, 500, "Get https://registry.example/v2/: dial tcp: i/o timeout")
		if err := h.eng.ImagePull(bg(t), img, "", nil); !contains(err, "i/o timeout") {
			t.Fatalf("ImagePull error = %v, want the daemon's message", err)
		}
	}},
	{"image_build", func(t *testing.T, h *harness) {
		var out bytes.Buffer
		opts := engine.BuildOptions{
			Context:    tarOf(t, map[string]string{"sub/Dockerfile": "FROM scratch\n", "app.txt": "hi"}),
			Tags:       []string{img, imgB},
			Dockerfile: "sub/Dockerfile",
			BuildArgs:  map[string]string{"VERSION": "1.2.3"},
			Labels:     map[string]string{"dev.vulnsuite.id": "app"},
			NoCache:    true,
			Platform:   "linux/arm64",
		}
		if err := h.eng.ImageBuild(bg(t), opts, &out); err != nil {
			t.Fatal(err)
		}
		if out.Len() == 0 {
			t.Error("ImageBuild wrote no build output to out")
		}
		b := h.lastBuild(t)
		if !reflect.DeepEqual(b.Tags, opts.Tags) || b.Dockerfile != opts.Dockerfile || !reflect.DeepEqual(b.BuildArgs, opts.BuildArgs) ||
			!reflect.DeepEqual(b.Labels, opts.Labels) || !b.NoCache || b.Platform != opts.Platform {
			t.Errorf("daemon saw build %+v, want the options %+v", b, opts)
		}
		if b.Files["app.txt"] != "hi" || b.Files["sub/Dockerfile"] != "FROM scratch\n" {
			t.Errorf("build context reached the daemon as %v", b.Files)
		}
		mustExist(t, h, img, "linux/arm64", true)
		mustExist(t, h, imgB, "linux/arm64", true)
	}},
	{"image_build_failure", func(t *testing.T, h *harness) {
		h.failBuild("The command '/bin/sh -c false' returned a non-zero code: 1")
		var out bytes.Buffer
		err := h.eng.ImageBuild(bg(t), engine.BuildOptions{Context: tarOf(t, map[string]string{"Dockerfile": "FROM scratch\n"}), Tags: []string{img}}, &out)
		if !contains(err, "returned a non-zero code: 1") {
			t.Fatalf("ImageBuild error = %v, want the daemon's message", err)
		}
		if !strings.Contains(out.String(), "Step 1/") {
			t.Errorf("the output before the failure did not reach out: %q", out.String())
		}
		mustExist(t, h, img, "", false)
	}},
	{"image_build_removes_intermediate_containers", func(t *testing.T, h *harness) {
		h.needsDaemon(t)
		h.divergence(t, map[string]string{api: pr73})
		if err := h.eng.ImageBuild(bg(t), engine.BuildOptions{Context: tarOf(t, nil), Tags: []string{img}}, nil); err != nil {
			t.Fatal(err)
		}
		q := h.lastBuild(t).Query
		// rm defaults to on in dockerd (the SDK leaves it out); forcerm must
		// be asked for.
		if q.Get("rm") == "0" || q.Get("forcerm") != "1" {
			t.Fatalf("build query rm=%q forcerm=%q; want rm on and forcerm=1, so a failed step leaves no container", q.Get("rm"), q.Get("forcerm"))
		}
	}},
	{"image_tag", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		if err := h.eng.ImageTag(bg(t), img, "registry.example/vs/app:moving"); err != nil {
			t.Fatal(err)
		}
		mustExist(t, h, "registry.example/vs/app:moving", "", true)
		if err := h.eng.ImageTag(bg(t), imgB, "registry.example/vs/other:x"); err == nil {
			t.Fatal("tagging a missing image must fail")
		}
	}},
	{"image_push", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		if err := h.eng.ImagePush(bg(t), img, nil); err != nil {
			t.Fatal(err)
		}
		if err := h.eng.ImagePush(bg(t), imgB, nil); err == nil {
			t.Fatal("pushing a missing image must fail")
		}
	}},
	{"image_remove", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		if err := h.eng.ImageRemove(bg(t), img, true); err != nil {
			t.Fatal(err)
		}
		mustExist(t, h, img, "", false)
		if err := h.eng.ImageRemove(bg(t), img, true); err != nil {
			t.Fatalf("removing an image that is already gone: %v, want nil", err)
		}
	}},
	{"image_remove_failure_is_error", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		h.failImageRemove(t, img, "image is being used by running container 0123")
		if err := h.eng.ImageRemove(bg(t), img, false); !contains(err, "being used") {
			t.Fatalf("ImageRemove error = %v, want the daemon's message", err)
		}
		mustExist(t, h, img, "", true)
	}},
	{"image_list_prefix", func(t *testing.T, h *harness) {
		for _, r := range []string{img, imgB, foreign} {
			h.seedImage(r, "")
		}
		got, err := h.eng.ImageList(bg(t), "registry.example/vs/")
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(got)
		if want := []string{img, imgB}; !reflect.DeepEqual(got, want) {
			t.Fatalf("ImageList = %v, want %v", got, want)
		}
	}},

	// -- containers -------------------------------------------------------------------
	{"container_create_inspect_roundtrip", func(t *testing.T, h *harness) {
		spec := engine.ContainerSpec{
			Name:   "vs-app",
			Labels: map[string]string{"dev.vulnsuite.managed": "true", "dev.vulnsuite.id": "app"},
			Ports: []engine.PortBinding{
				{HostIP: "127.0.0.1", ContainerPort: 80},
				{HostIP: "127.0.0.1", HostPort: 18443, ContainerPort: 443},
				{HostIP: "127.0.0.1", ContainerPort: 53, Protocol: "udp"},
			},
			Network: &engine.NetworkAttachment{Name: "vs-net", Aliases: []string{"app"}},
		}
		id := create(t, h, spec)
		d, err := h.eng.ContainerInspect(bg(t), "vs-app")
		if err != nil {
			t.Fatal(err)
		}
		if d.ID != id || d.Name != "vs-app" || d.Image != img || d.Running {
			t.Fatalf("created container inspects as %+v; want id %s, name vs-app, image %s, not running", d, id, img)
		}
		if err := h.eng.ContainerStart(bg(t), id); err != nil {
			t.Fatal(err)
		}
		d, err = h.eng.ContainerInspect(bg(t), id)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Running || d.Name != "vs-app" {
			t.Fatalf("started container inspects as %+v", d)
		}
		if d.IPs["vs-net"] == "" {
			t.Errorf("no address on vs-net: %v", d.IPs)
		}
		if p := d.Ports["80/tcp"]; p.IP != "127.0.0.1" || p.Port <= 0 {
			t.Errorf("80/tcp bound to %+v, want 127.0.0.1 and a daemon-assigned port (all ports: %v)", p, d.Ports)
		}
		if p := d.Ports["443/tcp"]; p != (engine.HostBinding{IP: "127.0.0.1", Port: 18443}) {
			t.Errorf("443/tcp bound to %+v, want 127.0.0.1:18443", p)
		}
		if p := d.Ports["53/udp"]; p.Port <= 0 {
			t.Errorf("53/udp not reported under its protocol: %v", d.Ports)
		}
	}},
	{"container_list_labels_and_state", func(t *testing.T, h *harness) {
		labels := map[string]string{"dev.vulnsuite.managed": "true", "dev.vulnsuite.state": "vulnerable"}
		run(t, h, engine.ContainerSpec{Name: "vs-a", Labels: labels})
		create(t, h, engine.ContainerSpec{Name: "vs-b"})
		run(t, h, engine.ContainerSpec{Name: "other-vs-c"})
		run(t, h, engine.ContainerSpec{Name: "xvs-d"})

		rows, err := h.eng.ContainerList(bg(t), false, "vs-")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Name != "vs-a" || rows[0].State != "running" || rows[0].Image != img || !reflect.DeepEqual(rows[0].Labels, labels) {
			t.Fatalf("running list = %+v; want only vs-a, running, image %s, labels %v", rows, img, labels)
		}
		rows, err = h.eng.ContainerList(bg(t), true, "vs-")
		if err != nil {
			t.Fatal(err)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
		if len(rows) != 2 || rows[0].Name != "vs-a" || rows[1].Name != "vs-b" {
			t.Fatalf("full list = %+v; want vs-a and vs-b only (a name prefix, not a substring)", rows)
		}
		if rows[1].State != "created" {
			t.Errorf("a never-started container lists as %q, want created", rows[1].State)
		}
		h.exit("vs-a", 2)
		rows, _ = h.eng.ContainerList(bg(t), true, "vs-a")
		if len(rows) != 1 || rows[0].State != "exited" {
			t.Errorf("an exited container lists as %+v, want state exited", rows)
		}
	}},
	{"container_create_errors", func(t *testing.T, h *harness) {
		if _, err := h.eng.ContainerCreate(bg(t), engine.ContainerSpec{Name: "vs-x", Image: imgB}); err == nil {
			t.Error("creating from a missing image must fail")
		}
		create(t, h, engine.ContainerSpec{Name: "vs-dup"})
		if _, err := h.eng.ContainerCreate(bg(t), engine.ContainerSpec{Name: "vs-dup", Image: img}); err == nil {
			t.Error("creating a second container with the same name must fail")
		}
		if _, err := h.eng.ContainerCreate(bg(t), engine.ContainerSpec{Name: "vs-nonet", Image: img, Network: &engine.NetworkAttachment{Name: "vs-missing"}}); err == nil {
			t.Error("creating a container on a missing network must fail")
		}
	}},
	{"container_start_missing_is_error", func(t *testing.T, h *harness) {
		if err := h.eng.ContainerStart(bg(t), "vs-missing"); err == nil {
			t.Fatal("starting a missing container must fail")
		}
	}},
	{"container_inspect_missing_is_error", func(t *testing.T, h *harness) {
		if d, err := h.eng.ContainerInspect(bg(t), "vs-missing"); err == nil {
			t.Fatalf("inspecting a missing container = %+v, nil; want an error", d)
		}
	}},
	{"container_remove", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		// Force-removes even a running container.
		if err := h.eng.ContainerRemove(bg(t), "vs-a"); err != nil {
			t.Fatal(err)
		}
		if _, err := h.eng.ContainerInspect(bg(t), "vs-a"); err == nil {
			t.Fatal("the removed container still inspects")
		}
		if rows, _ := h.eng.ContainerList(bg(t), true, "vs-"); len(rows) != 0 {
			t.Fatalf("the removed container still lists: %+v", rows)
		}
		if err := h.eng.ContainerRemove(bg(t), "vs-a"); err != nil {
			t.Fatalf("removing a container that is already gone: %v, want nil", err)
		}
	}},
	{"container_remove_failure_is_error", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		h.failContainerRemove(t, "vs-a", "driver failed to remove root filesystem")
		if err := h.eng.ContainerRemove(bg(t), "vs-a"); !contains(err, "root filesystem") {
			t.Fatalf("ContainerRemove error = %v, want the daemon's message", err)
		}
	}},
	{"container_exec", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		h.onExec(t, func(c, cmd string) (int, string) {
			if c != "vs-a" || cmd != "cat /etc/passwd | head -1" {
				t.Errorf("exec reached the daemon as %q in %q", cmd, c)
			}
			return 3, "root:x:0:0\n"
		})
		code, out, err := h.eng.ContainerExec(bg(t), "vs-a", "cat /etc/passwd | head -1", 5*time.Second)
		if err != nil || code != 3 || out != "root:x:0:0\n" {
			t.Fatalf("ContainerExec = %d, %q, %v; want 3, the output, nil", code, out, err)
		}
	}},
	{"container_exec_needs_running_container", func(t *testing.T, h *harness) {
		h.onExec(t, func(string, string) (int, string) { return 0, "" })
		if _, _, err := h.eng.ContainerExec(bg(t), "vs-missing", "true", 5*time.Second); err == nil {
			t.Error("exec in a missing container must fail")
		}
		create(t, h, engine.ContainerSpec{Name: "vs-stopped"})
		if _, _, err := h.eng.ContainerExec(bg(t), "vs-stopped", "true", 5*time.Second); err == nil {
			t.Error("exec in a container that is not running must fail")
		}
	}},
	{"container_logs", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		h.setLogs("listening on :80\nready\n")
		got, err := h.eng.ContainerLogs(bg(t), "vs-a", 50)
		if err != nil || got != "listening on :80\nready\n" {
			t.Fatalf("ContainerLogs = %q, %v", got, err)
		}
		if _, err := h.eng.ContainerLogs(bg(t), "vs-missing", 50); err == nil {
			t.Fatal("logs of a missing container must fail")
		}
	}},
	{"container_wait", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		type res struct {
			code int
			err  error
		}
		done := make(chan res, 1)
		go func() {
			code, err := h.eng.ContainerWait(bg(t), "vs-a")
			done <- res{code, err}
		}()
		select {
		case r := <-done:
			t.Fatalf("ContainerWait returned %d, %v while the container was still running", r.code, r.err)
		case <-time.After(100 * time.Millisecond):
		}
		h.exit("vs-a", 3)
		select {
		case r := <-done:
			if r.code != 3 || r.err != nil {
				t.Fatalf("ContainerWait = %d, %v; want 3, nil", r.code, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ContainerWait did not return after the container exited")
		}
		if code, err := h.eng.ContainerWait(bg(t), "vs-a"); code != 3 || err != nil {
			t.Fatalf("ContainerWait on an exited container = %d, %v; want 3, nil", code, err)
		}
		if _, err := h.eng.ContainerWait(bg(t), "vs-missing"); err == nil {
			t.Fatal("waiting for a missing container must fail")
		}
	}},
	{"container_wait_daemon_error", func(t *testing.T, h *harness) {
		h.needsDaemon(t)
		h.divergence(t, map[string]string{api: pr73})
		run(t, h, engine.ContainerSpec{Name: "vs-a"})
		h.d.mu.Lock()
		h.d.waitErr["vs-a"] = "removal of container vs-a failed"
		h.d.mu.Unlock()
		h.exit("vs-a", 137)
		code, err := h.eng.ContainerWait(bg(t), "vs-a")
		if code != 137 || !contains(err, "removal of container vs-a failed") {
			t.Fatalf("ContainerWait = %d, %v; want 137 and the daemon's error", code, err)
		}
	}},

	// -- networks -------------------------------------------------------------------
	{"network_ensure_creates", func(t *testing.T, h *harness) {
		spec := engine.NetworkSpec{Name: "vs-new", Internal: true, Subnet: "10.77.0.0/24", Gateway: "10.77.0.1"}
		id, err := h.eng.NetworkEnsure(bg(t), spec)
		if err != nil || id == "" {
			t.Fatalf("NetworkEnsure = %q, %v", id, err)
		}
		got, ok := h.network("vs-new")
		if !ok || !got.Internal || got.Subnet != spec.Subnet || got.Gateway != spec.Gateway {
			t.Fatalf("created network %+v (exists %v), want %+v", got, ok, spec)
		}
		if again, err := h.eng.NetworkEnsure(bg(t), spec); err != nil || again != id {
			t.Fatalf("second NetworkEnsure = %q, %v; want the same id %q", again, err, id)
		}
	}},
	{"network_ensure_keeps_existing", func(t *testing.T, h *harness) {
		h.divergence(t, map[string]string{fake: pr81})
		id := h.seedNetwork(engine.NetworkSpec{Name: "vs-net", Internal: true})
		got, err := h.eng.NetworkEnsure(bg(t), engine.NetworkSpec{Name: "vs-net", Internal: false})
		if err != nil || got != id {
			t.Fatalf("NetworkEnsure on an existing network = %q, %v; want its id %q", got, err, id)
		}
		if spec, _ := h.network("vs-net"); !spec.Internal {
			t.Fatal("NetworkEnsure changed an existing network; it must return it unchanged")
		}
	}},
	{"network_ensure_inspect_error_is_error", func(t *testing.T, h *harness) {
		h.fail(t, "GET", `^/networks/vs-net$`, 500, "network store unavailable")
		if _, err := h.eng.NetworkEnsure(bg(t), engine.NetworkSpec{Name: "vs-net"}); !contains(err, "network store unavailable") {
			t.Fatalf("NetworkEnsure error = %v, want the daemon's message", err)
		}
		if _, ok := h.network("vs-net"); ok {
			t.Fatal("NetworkEnsure created a network although it could not tell whether one exists")
		}
	}},
	{"network_ensure_create_race", func(t *testing.T, h *harness) {
		// A concurrent run creates the network between our inspect and create.
		f := h.fail(t, "POST", `^/networks/create$`, 409, "network with name vs-net already exists")
		f.once = true
		var raced string
		f.then = func(d *daemon) { raced = d.putNetwork(engine.NetworkSpec{Name: "vs-net"}, nil).id }
		got, err := h.eng.NetworkEnsure(bg(t), engine.NetworkSpec{Name: "vs-net"})
		if err != nil || got != raced {
			t.Fatalf("NetworkEnsure after losing the create race = %q, %v; want the winner's id %q", got, err, raced)
		}
	}},
	{"network_exists", func(t *testing.T, h *harness) {
		h.seedNetwork(engine.NetworkSpec{Name: "vs-net"})
		for name, want := range map[string]bool{"vs-net": true, "vs-missing": false} {
			if got, err := h.eng.NetworkExists(bg(t), name); err != nil || got != want {
				t.Errorf("NetworkExists(%s) = %v, %v; want %v, nil", name, got, err, want)
			}
		}
	}},
	{"network_exists_daemon_error_is_error", func(t *testing.T, h *harness) {
		h.fail(t, "GET", `^/networks/`, 500, "boom")
		if ok, err := h.eng.NetworkExists(bg(t), "vs-net"); err == nil {
			t.Fatalf("NetworkExists = %v, nil; a daemon 500 must be an error", ok)
		}
	}},
	{"network_remove", func(t *testing.T, h *harness) {
		h.seedNetwork(engine.NetworkSpec{Name: "vs-net"})
		if err := h.eng.NetworkRemove(bg(t), "vs-net"); err != nil {
			t.Fatal(err)
		}
		if ok, err := h.eng.NetworkExists(bg(t), "vs-net"); ok || err != nil {
			t.Fatalf("after removal NetworkExists = %v, %v", ok, err)
		}
		if err := h.eng.NetworkRemove(bg(t), "vs-net"); err != nil {
			t.Fatalf("removing a network that is already gone: %v, want nil", err)
		}
	}},
	{"network_remove_in_use_is_error", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a", Network: &engine.NetworkAttachment{Name: "vs-net"}})
		if err := h.eng.NetworkRemove(bg(t), "vs-net"); err == nil {
			t.Fatal("removing a network with attached containers must fail")
		}
		if ok, _ := h.eng.NetworkExists(bg(t), "vs-net"); !ok {
			t.Fatal("the in-use network was removed")
		}
	}},
	{"network_connect", func(t *testing.T, h *harness) {
		run(t, h, engine.ContainerSpec{Name: "vs-a", Network: &engine.NetworkAttachment{Name: "vs-front"}})
		h.seedNetwork(engine.NetworkSpec{Name: "vs-back"})
		if err := h.eng.NetworkConnect(bg(t), "vs-back", "vs-a", []string{"db"}); err != nil {
			t.Fatal(err)
		}
		d, err := h.eng.ContainerInspect(bg(t), "vs-a")
		if err != nil {
			t.Fatal(err)
		}
		if d.IPs["vs-front"] == "" || d.IPs["vs-back"] == "" {
			t.Fatalf("after connect the container has addresses %v, want one on vs-front and on vs-back", d.IPs)
		}
		if err := h.eng.NetworkConnect(bg(t), "vs-back", "vs-a", nil); err == nil {
			t.Error("connecting a container to a network it is already on must fail")
		}
		if err := h.eng.NetworkConnect(bg(t), "vs-missing", "vs-a", nil); err == nil {
			t.Error("connecting to a missing network must fail")
		}
		if err := h.eng.NetworkConnect(bg(t), "vs-back", "vs-missing", nil); err == nil {
			t.Error("connecting a missing container must fail")
		}
	}},

	// -- cancellation -----------------------------------------------------------------
	{"cancelled_context_is_error", func(t *testing.T, h *harness) {
		h.seedImage(img, "")
		h.seedNetwork(engine.NetworkSpec{Name: "vs-net"})
		h.seedNetwork(engine.NetworkSpec{Name: "vs-other"})
		run(t, h, engine.ContainerSpec{Name: "vs-a", Network: &engine.NetworkAttachment{Name: "vs-net"}})
		create(t, h, engine.ContainerSpec{Name: "vs-b"})
		h.onExec(t, func(string, string) (int, string) { return 0, "" })
		h.exit("vs-a", 0) // so a wait that ignored ctx would return at once
		ctx := cancelled()
		calls := map[string]func() error{
			"Ping":        func() error { _, err := h.eng.Ping(ctx); return err },
			"Info":        func() error { _, err := h.eng.Info(ctx); return err },
			"ImageExists": func() error { _, err := h.eng.ImageExists(ctx, img, ""); return err },
			"ImagePull":   func() error { return h.eng.ImagePull(ctx, imgB, "", nil) },
			"ImageBuild": func() error {
				return h.eng.ImageBuild(ctx, engine.BuildOptions{Context: tarOf(t, nil), Tags: []string{imgB}}, nil)
			},
			"ImageTag":    func() error { return h.eng.ImageTag(ctx, img, imgB) },
			"ImagePush":   func() error { return h.eng.ImagePush(ctx, img, nil) },
			"ImageRemove": func() error { return h.eng.ImageRemove(ctx, img, true) },
			"ImageList":   func() error { _, err := h.eng.ImageList(ctx, ""); return err },
			"ContainerCreate": func() error {
				_, err := h.eng.ContainerCreate(ctx, engine.ContainerSpec{Name: "vs-c", Image: img})
				return err
			},
			"ContainerStart":   func() error { return h.eng.ContainerStart(ctx, "vs-b") },
			"ContainerRemove":  func() error { return h.eng.ContainerRemove(ctx, "vs-b") },
			"ContainerList":    func() error { _, err := h.eng.ContainerList(ctx, true, ""); return err },
			"ContainerInspect": func() error { _, err := h.eng.ContainerInspect(ctx, "vs-b"); return err },
			"ContainerExec":    func() error { _, _, err := h.eng.ContainerExec(ctx, "vs-b", "true", time.Second); return err },
			"ContainerLogs":    func() error { _, err := h.eng.ContainerLogs(ctx, "vs-b", 10); return err },
			"ContainerWait":    func() error { _, err := h.eng.ContainerWait(ctx, "vs-a"); return err },
			"NetworkEnsure":    func() error { _, err := h.eng.NetworkEnsure(ctx, engine.NetworkSpec{Name: "vs-net"}); return err },
			"NetworkExists":    func() error { _, err := h.eng.NetworkExists(ctx, "vs-net"); return err },
			"NetworkRemove":    func() error { return h.eng.NetworkRemove(ctx, "vs-other") },
			"NetworkConnect":   func() error { return h.eng.NetworkConnect(ctx, "vs-other", "vs-b", nil) },
		}
		names := make([]string, 0, len(calls))
		for n := range calls {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := calls[n](); err == nil {
				t.Errorf("%s with a cancelled context succeeded; it must fail", n)
			} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
				t.Errorf("%s with a cancelled context = %v; want an error wrapping context.Canceled", n, err)
			}
		}
	}},
}
