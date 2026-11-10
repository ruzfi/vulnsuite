package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// groupFixtures writes a templates tree with a three-member variant group
// (php2shell), an ungrouped target, and a single-member nickname group.
func groupFixtures(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(cat, id, extra string) {
		dir := filepath.Join(root, cat, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		doc := fmt.Sprintf(`apiVersion: vulnsuite/v1
kind: Target
metadata:
  id: %s
  summary: demo
  vuln_refs: [CVE-2026-1]%s
base: { kind: image, image: nginx:1, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
    verify: [ { http: { path: /, status: 200 } } ]
`, id, extra)
		if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web-apps", "php2shell-base", "\n  group: php2shell\n  primary: true")
	write("web-apps", "php2shell-waf", "\n  group: php2shell\n  variant: waf-evasion")
	write("web-apps", "php2shell-chunked", "\n  group: php2shell\n  variant: chunked")
	write("web-apps", "standalone", "")
	write("databases", "redis-rce", "\n  group: redis-nick")
	return root
}

func isolateHome(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("NUCLEI_TEMPLATES", "")
}

func TestListGroupsCollapse(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)

	// Default: groups collapse to the primary; the badge shows family size.
	code, out, _ := run(t, nil, "-T", root, "list")
	if code != ExitOK {
		t.Fatalf("list: %d\n%s", code, out)
	}
	if !strings.Contains(out, "php2shell (+2)") {
		t.Fatalf("expected collapsed badge php2shell (+2):\n%s", out)
	}
	if strings.Contains(out, "php2shell-waf") || strings.Contains(out, "php2shell-chunked") {
		t.Fatalf("variants should be hidden by default:\n%s", out)
	}
	// 3 rows: primary + standalone + nickname.
	if !strings.Contains(out, "3 templates") {
		t.Fatalf("expected 3 templates collapsed:\n%s", out)
	}

	// -variants expands every member.
	code, out, _ = run(t, nil, "-T", root, "list", "-variants")
	if code != ExitOK || !strings.Contains(out, "php2shell-waf") || !strings.Contains(out, "php2shell-chunked") {
		t.Fatalf("list -variants:\n%s", out)
	}
	if !strings.Contains(out, "5 templates") {
		t.Fatalf("expected 5 templates expanded:\n%s", out)
	}
}

func TestListGroupFilter(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)
	code, out, _ := run(t, nil, "-json", "-T", root, "list", "-group", "php2shell")
	var rows []listRow
	if code != ExitOK || json.Unmarshal([]byte(out), &rows) != nil {
		t.Fatalf("list -group json: %d\n%s", code, out)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 members, got %d: %s", len(rows), out)
	}
	for _, r := range rows {
		if r.Group != "php2shell" {
			t.Fatalf("row not in group: %+v", r)
		}
	}
	// Unknown handle is an error.
	if code, _, _ := run(t, nil, "-T", root, "list", "-group", "nope"); code == ExitOK {
		t.Fatal("unknown -group should fail")
	}
}

func TestInfoFamily(t *testing.T) {
	isolateHome(t)
	root := groupFixtures(t)

	// info <group> prints the family (all members + discriminators).
	code, out, _ := run(t, nil, "-T", root, "info", "php2shell")
	if code != ExitOK {
		t.Fatalf("info group: %d\n%s", code, out)
	}
	for _, want := range []string{"variant group", "php2shell-base", "waf-evasion", "chunked"} {
		if !strings.Contains(out, want) {
			t.Fatalf("info family missing %q:\n%s", want, out)
		}
	}

	// info <exact-id> still shows a single target's detail, not the family.
	code, out, _ = run(t, nil, "-T", root, "info", "php2shell-waf")
	if code != ExitOK || strings.Contains(out, "variant group") {
		t.Fatalf("info exact id should be single-target:\n%s", out)
	}
}
