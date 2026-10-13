package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
	"github.com/ruzfi/vulnsuite/pkg/engine/enginetest"
	"github.com/ruzfi/vulnsuite/pkg/loader"
)

func store(t *testing.T) *loader.Store {
	t.Helper()
	root, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "templates"))
	return loader.New(root)
}

func TestImageKindPullsAndReuses(t *testing.T) {
	fe := enginetest.New()
	b := New(fe)
	c, err := store(t).LoadSelector("grafana-8.3.0-cve-2021-43798")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil || r.Ref != "grafana/grafana:8.3.0" || !r.Pulled || r.Built {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = b.Resolve(ctx, c, "patched", Options{Pull: true})
	if err != nil || r.Ref != "grafana/grafana:8.3.1" || !r.Pulled {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil || r.Pulled || r.Built {
		t.Fatalf("second resolve must reuse: %+v %v", r, err)
	}
	if len(fe.Pulls) != 2 || len(fe.Builds) != 0 {
		t.Fatalf("pulls=%v builds=%d", fe.Pulls, len(fe.Builds))
	}
	// pull disabled and image missing -> error
	if _, err := New(enginetest.New()).Resolve(ctx, c, "vulnerable", Options{Pull: false}); err == nil {
		t.Fatal("expected error with pulling disabled")
	}
}

func TestOverlayBuildGeneratesDockerfile(t *testing.T) {
	fe := enginetest.New()
	b := New(fe)
	c, err := store(t).LoadSelector("apache-httpd-2.4.49-cve-2021-41773")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil || !r.Built || r.BuildKind != contract.BuildKindOverlay {
		t.Fatalf("%+v %v", r, err)
	}
	if fe.Pulls[0] != "httpd:2.4.49" {
		t.Fatalf("base must be pulled first: %v", fe.Pulls)
	}
	bl := fe.Builds[0]
	df := bl.Files["Dockerfile"]
	if !strings.HasPrefix(df, "FROM httpd:2.4.49\n") || !strings.Contains(df, "COPY overlay_0_httpd.conf /usr/local/apache2/conf/httpd.conf") {
		t.Fatalf("dockerfile:\n%s", df)
	}
	want, _ := os.ReadFile(filepath.Join(c.Folder, "files", "vuln", "httpd.conf"))
	if bl.Files["overlay_0_httpd.conf"] != string(want) {
		t.Fatal("overlay content must be carried into the context")
	}
	if bl.Labels[LabelID] != c.ID() || bl.Labels[LabelState] != "vulnerable" || bl.Labels[LabelHash] != c.ContentHash("vulnerable") {
		t.Fatalf("labels: %v", bl.Labels)
	}
	if bl.Tags[0] != c.ImageTag("vulnerable") || r.Ref != bl.Tags[0] {
		t.Fatalf("tag: %v vs %s", bl.Tags, r.Ref)
	}
	// content-addressed reuse
	r2, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true})
	if err != nil || r2.Built || len(fe.Builds) != 1 {
		t.Fatal("expected reuse")
	}
	// force rebuilds
	r3, err := b.Resolve(ctx, c, "vulnerable", Options{Pull: true, Force: true, NoCache: true})
	if err != nil || !r3.Built || len(fe.Builds) != 2 || !fe.Builds[1].NoCache {
		t.Fatal("expected a forced rebuild")
	}
	// redis: overlay + env baked in
	rc, _ := store(t).LoadSelector("redis-unauthenticated-access")
	if _, err := b.Resolve(ctx, rc, "patched", Options{Pull: true}); err != nil {
		t.Fatal(err)
	}
	if df := fe.Builds[len(fe.Builds)-1].Files["Dockerfile"]; !strings.Contains(df, "/etc/redis/redis.conf") {
		t.Fatal(df)
	}
}

func TestLocalBuildContextAndEnv(t *testing.T) {
	fe := enginetest.New()
	b := New(fe)
	c, err := store(t).LoadSelector("exposed-dotenv-file")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := b.Resolve(ctx, c, "patched", Options{})
	if err != nil || !r.Built || r.BuildKind != contract.BuildKindBuild {
		t.Fatalf("%+v %v", r, err)
	}
	bl := fe.Builds[0]
	if _, ok := bl.Files["app.py"]; !ok {
		t.Fatalf("context files: %v", keys(bl.Files))
	}
	if !strings.Contains(bl.Files["Dockerfile"], "\nENV MODE=patched\n") {
		t.Fatalf("state env must be baked into the image:\n%s", bl.Files["Dockerfile"])
	}
	// iot: patched overlays app.py onto the context
	ic, _ := store(t).LoadSelector("iot-camera-auth-bypass")
	if _, err := b.Resolve(ctx, ic, "patched", Options{}); err != nil {
		t.Fatal(err)
	}
	patched, _ := os.ReadFile(filepath.Join(ic.Folder, "files", "app_patched.py"))
	if fe.Builds[1].Files["app.py"] != string(patched) {
		t.Fatal("overlay must replace the context file")
	}
	if ic.ContentHash("vulnerable") == ic.ContentHash("patched") {
		t.Fatal("overlayed context must change the hash")
	}
}

func TestResolveAllParallelAndPublish(t *testing.T) {
	fe := enginetest.New()
	b := New(fe)
	s := store(t)
	var jobs []Job
	for _, id := range []string{"apache-httpd-2.4.49-cve-2021-41773", "grafana-8.3.0-cve-2021-43798", "exposed-dotenv-file"} {
		c, err := s.LoadSelector(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range contract.StateNames {
			jobs = append(jobs, Job{Contract: c, State: st})
		}
	}
	var done int
	out := b.ResolveAll(context.Background(), jobs, 3, Options{Pull: true}, func(Outcome) { done++ })
	if done != 6 || len(out) != 6 {
		t.Fatalf("done=%d out=%d", done, len(out))
	}
	for _, o := range out {
		if o.Err != nil {
			t.Fatalf("%s/%s: %v", o.Job.Contract.ID(), o.Job.State, o.Err)
		}
	}
	// publish the apache vulnerable image
	pushed, err := b.Publish(context.Background(), jobs[0].Contract, "vulnerable", "ghcr.io/ruzfi/vulnsuite/", nil)
	if err != nil || len(pushed) != 2 {
		t.Fatalf("%v %v", pushed, err)
	}
	if pushed[1] != "ghcr.io/ruzfi/vulnsuite/apache-httpd-2.4.49-cve-2021-41773:vulnerable" ||
		!strings.HasPrefix(pushed[0], pushed[1]+"-") {
		t.Fatalf("refs: %v", pushed)
	}
	// a failing build is reported per job with its log
	fe2 := enginetest.New()
	fe2.FailBuild = "boom"
	res := New(fe2).ResolveAll(context.Background(), jobs[:1], 1, Options{Pull: true}, nil)
	if res[0].Err == nil || !strings.Contains(res[0].Log, "Step 1/1") {
		t.Fatalf("expected failure with log: %+v", res[0])
	}
}

func TestOverlayDockerfileQuoting(t *testing.T) {
	df := overlayDockerfile("img:1", []overlayEntry{{local: "f", dest: "/etc/f", mode: "0600"}}, map[string]string{"B": "x y", "A": `q"uote`})
	want := "FROM img:1\nCOPY f /etc/f\nRUN chmod 0600 /etc/f\nENV A=\"q\\\"uote\"\nENV B=\"x y\"\n"
	if df != want {
		t.Fatalf("got:\n%s\nwant:\n%s", df, want)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
