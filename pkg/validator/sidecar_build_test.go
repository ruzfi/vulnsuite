package validator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ruzfi/vulnsuite/pkg/contract"
)

// builtSidecarDoc is base with a "driver" sidecar built from BUILD.
func builtSidecarDoc(build, patched string) string {
	doc := strings.Replace(base, "healthcheck:", "sidecars: [ { name: driver, build: "+build+", command: [sleep, infinity] } ], healthcheck:", 1)
	return strings.Replace(doc, "  patched:\n", "  patched:\n"+patched, 1)
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A built sidecar is pinned by its content: no unpinned-sidecar, even when
// -allow-unpinned is off, while an unpinned override of it still is one.
func TestBuiltSidecarIsPinned(t *testing.T) {
	c := parse(t, builtSidecarDoc("{ context: sidecars/driver }", ""))
	writeFiles(t, c.Folder, map[string]string{"sidecars/driver/Dockerfile": "FROM busybox\n"})
	fs := (&Validator{}).Check(c)
	if got := findingsFor(fs, "unpinned-sidecar"); len(got) > 0 {
		t.Fatalf("a built sidecar raised %v", got)
	}
	for _, f := range fs {
		if f.Level == Error {
			t.Errorf("unexpected error: %s", f)
		}
	}
	c = parse(t, builtSidecarDoc("{ context: sidecars/driver }", "    sidecars: { driver: { image: busybox:1.36.1 } }\n"))
	writeFiles(t, c.Folder, map[string]string{"sidecars/driver/Dockerfile": "FROM busybox\n"})
	if got := findingsFor((&Validator{}).Check(c), "unpinned-sidecar"); len(got) != 1 || !strings.Contains(got[0].Message, "states.patched.sidecars.driver") {
		t.Fatalf("an unpinned override of a built sidecar: %v", got)
	}
}

// missing-context, missing-dockerfile and path-escapes-template cover a
// sidecar's build, naming the sidecar.
func TestBuiltSidecarFiles(t *testing.T) {
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"Dockerfile": "FROM host\n"})
	cases := []struct {
		name, build string
		files       map[string]string
		link        [2]string // a symlink to create: rel path -> target
		rule, msg   string    // "" = no finding
	}{
		{"present", "{ context: sidecars/driver }", map[string]string{"sidecars/driver/Dockerfile": "FROM x\n"}, [2]string{}, "", ""},
		{"own dockerfile", "{ context: sidecars/driver, dockerfile: build/Dockerfile.driver }",
			map[string]string{"sidecars/driver/build/Dockerfile.driver": "FROM x\n"}, [2]string{}, "", ""},
		{"no context", "{ context: sidecars/driver }", nil, [2]string{},
			"missing-context", "sidecar driver: build context sidecars/driver not found"},
		{"context is a file", "{ context: sidecars/driver }", map[string]string{"sidecars/driver": "x"}, [2]string{},
			"missing-context", "sidecar driver: build context sidecars/driver not found"},
		{"no dockerfile", "{ context: sidecars/driver }", map[string]string{"sidecars/driver/run.sh": "x"}, [2]string{},
			"missing-dockerfile", "sidecar driver: build context sidecars/driver has no Dockerfile"},
		{"no named dockerfile", "{ context: sidecars/driver, dockerfile: Dockerfile.alt }", map[string]string{"sidecars/driver/Dockerfile": "FROM x\n"}, [2]string{},
			"missing-dockerfile", "has no Dockerfile.alt"},
		{"context escapes", "{ context: sidecars/driver }", nil, [2]string{"sidecars/driver", outside},
			"path-escapes-template", "sidecar driver: build context sidecars/driver resolves outside"},
		{"dockerfile escapes", "{ context: sidecars/driver }", map[string]string{"sidecars/driver/run.sh": "x"},
			[2]string{"sidecars/driver/Dockerfile", filepath.Join(outside, "Dockerfile")},
			"path-escapes-template", "sidecar driver: dockerfile Dockerfile resolves outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := parse(t, builtSidecarDoc(tc.build, ""))
			writeFiles(t, c.Folder, tc.files)
			if tc.link[0] != "" {
				p := filepath.Join(c.Folder, filepath.FromSlash(tc.link[0]))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tc.link[1], p); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			fs := (&Validator{}).Check(c)
			var got []Finding
			for _, r := range []string{"missing-context", "missing-dockerfile", "path-escapes-template"} {
				got = append(got, findingsFor(fs, r)...)
			}
			switch {
			case tc.rule == "" && len(got) > 0:
				t.Fatalf("unexpected %v", got)
			case tc.rule != "" && (len(got) != 1 || got[0].Rule != tc.rule || got[0].Level != Error || !strings.Contains(got[0].Message, tc.msg)):
				t.Fatalf("want one %s containing %q, got %v", tc.rule, tc.msg, got)
			}
		})
	}
}

// identical-states: a built sidecar is the same image in both states unless
// one of them swaps it for an image.
func TestIdenticalStatesWithBuiltSidecar(t *testing.T) {
	v := &Validator{}
	c := parse(t, builtSidecarDoc("{ context: sidecars/driver }", ""))
	writeFiles(t, c.Folder, map[string]string{"sidecars/driver/Dockerfile": "FROM busybox\n"})
	if rules(v.Check(c))["identical-states"] != Warning {
		t.Fatal("states differing in nothing, a built sidecar included, are identical")
	}
	c = parse(t, builtSidecarDoc("{ context: sidecars/driver }", "    sidecars: { driver: { image: busybox:1.36.1, digest: \""+pinned+"\" } }\n"))
	writeFiles(t, c.Folder, map[string]string{"sidecars/driver/Dockerfile": "FROM busybox\n"})
	if _, bad := rules(v.Check(c))["identical-states"]; bad {
		t.Fatal("a state that swaps the built sidecar for an image differs")
	}
	if c.SidecarImage(contract.StatePatched, c.Service.Sidecars[0]) == c.SidecarImage(contract.StateVulnerable, c.Service.Sidecars[0]) {
		t.Fatal("the override must resolve to another image")
	}
}
