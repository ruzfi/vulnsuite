package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// sidecarBuildHead is a contract whose "driver" sidecar is built from
// sidecars/driver; SIDECAR is replaced by its build mapping.
const sidecarBuildHead = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: sidecar-build, summary: x }
base: { kind: image, image: nginx:1.27, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service:
  ports: [ { container: 80, protocol: http } ]
  sidecars:
    - { name: driver, build: SIDECAR, command: [sleep, infinity], environment: { A: "1" } }
    - { name: db, image: redis:7, digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
states:
  vulnerable: {}
  patched:
    overlay: [ { src: files/a.conf, dest: /etc/a.conf } ]
`

// sidecarDoc parses a sidecarBuildHead variant into a template folder holding
// files (rel path -> content; a "+x:" prefix makes the file executable).
func sidecarDoc(t *testing.T, doc string, files map[string]string) *Contract {
	t.Helper()
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = t.TempDir()
	for rel, body := range files {
		mode := os.FileMode(0o644)
		if b, ok := strings.CutPrefix(body, "+x:"); ok {
			body, mode = b, 0o755
		}
		p := filepath.Join(c.Folder, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // past the umask
			t.Fatal(err)
		}
	}
	return c
}

var driverFiles = map[string]string{
	"sidecars/driver/Dockerfile": "FROM busybox\nCOPY run.sh /run.sh\n",
	"sidecars/driver/run.sh":     "+x:#!/bin/sh\necho hi\n",
	"files/a.conf":               "a",
}

func withFiles(over map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range driverFiles {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func TestSidecarBuildDecodes(t *testing.T) {
	c := sidecarDoc(t, strings.Replace(sidecarBuildHead, "SIDECAR", `{ context: sidecars/driver, build_args: { V: "2" } }`, 1), driverFiles)
	sc := c.Service.Sidecars[0]
	if sc.Build == nil || sc.Build.Context != "sidecars/driver" || sc.Build.DockerfilePath() != "Dockerfile" || sc.Build.BuildArgs["V"] != "2" {
		t.Fatalf("build not decoded: %+v", sc.Build)
	}
	if sc.Image != "" || sc.Ref() != "" || len(sc.Command) != 2 || sc.Environment["A"] != "1" {
		t.Fatalf("sidecar: %+v", sc)
	}
	if c.Service.Sidecars[1].Build != nil {
		t.Fatal("an image sidecar has no build")
	}
}

// The tag is vulnsuite/<id>:sidecar-<name>-<hash>, stable for identical
// inputs and changed by every build input, but not by run-time settings.
func TestSidecarTag(t *testing.T) {
	tag := func(build string, files map[string]string, mutate ...func(*Contract)) string {
		c := sidecarDoc(t, strings.Replace(sidecarBuildHead, "SIDECAR", build, 1), files)
		for _, m := range mutate {
			m(c)
		}
		return c.SidecarTag(c.Service.Sidecars[0])
	}
	const ctx = "{ context: sidecars/driver }"
	base := tag(ctx, driverFiles)
	if !regexp.MustCompile(`^vulnsuite/sidecar-build:sidecar-driver-[0-9a-f]{12}$`).MatchString(base) {
		t.Fatalf("tag %q", base)
	}
	if again := tag(ctx, driverFiles); again != base {
		t.Fatalf("tag not stable: %s vs %s", base, again)
	}
	if got := tag("{ context: sidecars/driver, dockerfile: Dockerfile }", driverFiles); got != base {
		t.Fatalf("the default dockerfile spelled out changed the tag: %s vs %s", got, base)
	}
	changed := map[string]string{
		"script content":  tag(ctx, withFiles(map[string]string{"sidecars/driver/run.sh": "+x:#!/bin/sh\necho bye\n"})),
		"new file":        tag(ctx, withFiles(map[string]string{"sidecars/driver/extra": "x"})),
		"Dockerfile":      tag(ctx, withFiles(map[string]string{"sidecars/driver/Dockerfile": "FROM alpine\nCOPY run.sh /run.sh\n"})),
		"dockerfile path": tag("{ context: sidecars/driver, dockerfile: Dockerfile.alt }", withFiles(map[string]string{"sidecars/driver/Dockerfile.alt": "FROM busybox\nCOPY run.sh /run.sh\n"})),
		"build args":      tag(`{ context: sidecars/driver, build_args: { V: "2" } }`, driverFiles),
	}
	// The exec bit only exists where the filesystem keeps one.
	if runtime.GOOS != "windows" {
		changed["exec bit"] = tag(ctx, withFiles(map[string]string{"sidecars/driver/run.sh": "#!/bin/sh\necho hi\n"}))
	}
	for what, got := range changed {
		if got == base {
			t.Errorf("%s must change the sidecar tag (%s)", what, got)
		}
	}
	// Run-time settings and files outside the context do not.
	same := map[string]string{
		"command":         tag(ctx, driverFiles, func(c *Contract) { c.Service.Sidecars[0].Command = []string{"true"} }),
		"environment":     tag(ctx, driverFiles, func(c *Contract) { c.Service.Sidecars[0].Environment = nil }),
		"file outside it": tag(ctx, withFiles(map[string]string{"files/a.conf": "b"})),
	}
	for what, got := range same {
		if got != base {
			t.Errorf("%s must not change the sidecar tag: %s vs %s", what, got, base)
		}
	}
	// The name is in the tag, not the hash.
	c := sidecarDoc(t, strings.Replace(sidecarBuildHead, "SIDECAR", ctx, 1), driverFiles)
	sc := c.Service.Sidecars[0]
	renamed := sc
	renamed.Name = "dns"
	if c.SidecarHash(renamed) != c.SidecarHash(sc) || !strings.Contains(c.SidecarTag(renamed), ":sidecar-dns-") {
		t.Fatalf("renamed: %s vs %s", c.SidecarTag(renamed), c.SidecarTag(sc))
	}
	if c.SidecarTag(c.Service.Sidecars[1]) != "" || c.SidecarHash(c.Service.Sidecars[1]) != "" {
		t.Fatal("an image sidecar has no built tag")
	}
}

// A context that escapes the template hashes as missing rather than reading
// a host file.
func TestSidecarTagEscapingContext(t *testing.T) {
	c := sidecarDoc(t, strings.Replace(sidecarBuildHead, "SIDECAR", "{ context: sidecars/driver }", 1), driverFiles)
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "Dockerfile"), []byte("FROM host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(c.Folder, "sidecars", "driver")); err != nil {
		t.Fatal(err)
	}
	missing := c.SidecarTag(c.Service.Sidecars[0])
	if err := os.Symlink(out, filepath.Join(c.Folder, "sidecars", "driver")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got := c.SidecarTag(c.Service.Sidecars[0]); got != missing {
		t.Fatalf("an escaping context must hash as missing: %s vs %s", got, missing)
	}
}

// Adding a built sidecar changes no state's image hash.
func TestBuiltSidecarLeavesStateHash(t *testing.T) {
	with := sidecarDoc(t, strings.Replace(sidecarBuildHead, "SIDECAR", "{ context: sidecars/driver }", 1), driverFiles)
	without := sidecarDoc(t, strings.Replace(sidecarBuildHead,
		"    - { name: driver, build: SIDECAR, command: [sleep, infinity], environment: { A: \"1\" } }\n", "", 1), driverFiles)
	for _, st := range []string{StateVulnerable, StatePatched} {
		if with.ContentHash(st) != without.ContentHash(st) || with.ImageRef(st) != without.ImageRef(st) {
			t.Fatalf("%s: a built sidecar changed the state image: %s vs %s", st, with.ImageRef(st), without.ImageRef(st))
		}
	}
}

func TestSidecarImage(t *testing.T) {
	doc := strings.Replace(sidecarBuildHead, "SIDECAR", "{ context: sidecars/driver }", 1)
	doc = strings.Replace(doc, "  patched:\n", "  patched:\n    sidecars: { driver: { image: busybox:1.36.1 }, db: { image: redis:8 } }\n", 1)
	c := sidecarDoc(t, doc, driverFiles)
	driver, db := c.Service.Sidecars[0], c.Service.Sidecars[1]
	vuln, patched := c.States[StateVulnerable], c.States[StatePatched]
	if !vuln.BuildsSidecar(driver) || patched.BuildsSidecar(driver) || vuln.BuildsSidecar(db) {
		t.Fatal("BuildsSidecar: a build, unless the state swaps it for an image")
	}
	cases := []struct{ state, want string }{
		{StateVulnerable, c.SidecarTag(driver)},
		{StatePatched, "busybox:1.36.1"},
	}
	for _, tc := range cases {
		if got := c.SidecarImage(tc.state, driver); got != tc.want {
			t.Errorf("driver in %s: %q, want %q", tc.state, got, tc.want)
		}
	}
	if got := c.SidecarImage(StateVulnerable, db); got != db.Ref() {
		t.Errorf("db in vulnerable: %q", got)
	}
	if got := c.SidecarImage(StatePatched, db); got != "redis:8" {
		t.Errorf("db in patched: %q", got)
	}
	// State.SidecarRef keeps its meaning: an override or the sidecar's image.
	if vuln.SidecarRef(driver) != "" || patched.SidecarRef(driver) != "busybox:1.36.1" {
		t.Error("SidecarRef changed")
	}
	if got := c.SidecarImage("nope", driver); got != c.SidecarTag(driver) {
		t.Errorf("an undeclared state: %q", got)
	}
}

// An image sidecar marshals exactly as before; a built one carries its build
// and no empty image.
func TestSidecarJSON(t *testing.T) {
	b, _ := json.Marshal(Sidecar{Name: "db", Image: "redis:7", Digest: "sha256:x"})
	if string(b) != `{"name":"db","image":"redis:7","digest":"sha256:x"}` {
		t.Fatalf("image sidecar JSON changed: %s", b)
	}
	b, _ = json.Marshal(Sidecar{Name: "driver", Build: &SidecarBuild{Context: "sidecars/driver"}})
	if string(b) != `{"name":"driver","build":{"context":"sidecars/driver"}}` {
		t.Fatalf("built sidecar JSON: %s", b)
	}
}

// The decoder rejects what the schema rejects, with the location named.
func TestSidecarBuildRejected(t *testing.T) {
	cases := map[string]string{
		`{ name: driver, image: busybox, build: { context: d } }`: "service/sidecars/0: set either image or build, not both",
		`{ name: driver, image: "", build: { context: d } }`:      "service/sidecars/0: set either image or build, not both",
		`{ name: driver, digest: "", build: { context: d } }`:     "service/sidecars/0/digest",
		`{ name: driver }`:                                            "service/sidecars/0: name and image are required",
		`{ name: "", build: { context: d } }`:                         "service/sidecars/0/name: is required",
		`{ name: -x, build: { context: d } }`:                         "service/sidecars/0/name",
		`{ name: driver, build: { context: "" } }`:                    "service/sidecars/0/build/context: is required",
		`{ name: driver, build: { context: a/../../b } }`:             "service/sidecars/0/build/context",
		`{ name: driver, build: { context: 'C:\x' } }`:                "service/sidecars/0/build/context",
		`{ name: driver, build: { context: d, dockerfile: /etc/x } }`: "service/sidecars/0/build/dockerfile",
		`{ name: driver, build: { context: d, dockerfile: "" } }`:     "service/sidecars/0/build/dockerfile",
	}
	for sc, want := range cases {
		doc := strings.Replace(sidecarBuildHead, "    - { name: driver, build: SIDECAR, command: [sleep, infinity], environment: { A: \"1\" } }", "    - "+sc, 1)
		_, err := Parse([]byte(doc))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", sc, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: want %q, got %v", sc, want, err)
		}
	}
	long := strings.Repeat("a", maxSidecarName+1)
	doc := strings.Replace(sidecarBuildHead, "name: driver, build: SIDECAR", "name: "+long+", build: { context: d }", 1)
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "at most 100") {
		t.Errorf("a long built sidecar name: %v", err)
	}
	// The same long name is fine on an image sidecar, as it always was.
	doc = strings.Replace(sidecarBuildHead, "name: driver, build: SIDECAR", "name: "+long+", image: busybox", 1)
	if _, err := Parse([]byte(doc)); err != nil {
		t.Errorf("a long image sidecar name: %v", err)
	}
}
