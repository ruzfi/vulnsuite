package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hashDoc(t *testing.T, doc string) *Contract {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "files"), 0o755)
	os.WriteFile(filepath.Join(dir, "files", "a.conf"), []byte("a"), 0o644)
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	c.Folder = dir
	return c
}

const hashHead = `apiVersion: vulnsuite/v1
kind: Target
metadata: { id: hash-inputs, summary: x }
base: { kind: image, image: httpd:2.4.49, digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }
service: { ports: [ { container: 80, protocol: http } ] }
states:
  vulnerable:
`

// Issue #41 item 1: an overlay build runs FROM the state's image override, so
// that image (and its digest) is part of the hash.
func TestContentHashCoversStateImage(t *testing.T) {
	mk := func(image string) string {
		return hashDoc(t, hashHead+"    image: "+image+"\n    overlay: [ { src: files/a.conf, dest: /etc/a.conf } ]\n").ContentHash("vulnerable")
	}
	h50, h51 := mk("httpd:2.4.50"), mk("httpd:2.4.51")
	if h50 == h51 {
		t.Fatalf("a different state image must change the hash (both %s)", h50)
	}
	d1 := mk("httpd:2.4.51\n    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111")
	d2 := mk("httpd:2.4.51\n    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222")
	if d1 == d2 || d1 == h51 {
		t.Fatalf("the state image digest must change the hash: %s %s %s", d1, d2, h51)
	}
}

// Issue #41 item 1: an overlay's mode is part of the hash.
func TestContentHashCoversOverlayMode(t *testing.T) {
	mk := func(mode string) string {
		return hashDoc(t, hashHead+`    overlay: [ { src: files/a.conf, dest: /etc/a.conf`+mode+` } ]`+"\n").ContentHash("vulnerable")
	}
	none, m644, m755 := mk(""), mk(`, mode: "0644"`), mk(`, mode: "0755"`)
	if m644 == m755 || none == m755 {
		t.Fatalf("overlay mode must change the hash: none=%s 0644=%s 0755=%s", none, m644, m755)
	}
}

// The new inputs are hashed only when set, so a template that uses neither a
// state image override nor an overlay mode keeps the tag it had before (no
// needless rebuild of every image).
func TestContentHashUnchangedWithoutNewInputs(t *testing.T) {
	c := hashDoc(t, hashHead+"    overlay: [ { src: files/a.conf, dest: /etc/a.conf } ]\n    environment: { A: \"1\" }\n")
	// The recipe before the state image / mode / platform inputs were added.
	sumA := sha256.Sum256([]byte("a"))
	legacy := strings.Join([]string{
		"image:httpd:2.4.49@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"overlay:/etc/a.conf:" + hex.EncodeToString(sumA[:])[:16],
		`env:{"A":"1"}`,
	}, "|")
	sum := sha256.Sum256([]byte(legacy))
	if got, want := c.ContentHash("vulnerable"), hex.EncodeToString(sum[:])[:12]; got != want {
		t.Fatalf("hash of a template without the new inputs changed: got %s, want %s", got, want)
	}
}

// #47 item 7: symlinks in a build context are sent as symlinks, so the hash
// covers their link text (and never reads through them).
func TestHashTreeCoversSymlinks(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a"), []byte("a"), 0o644)
	plain := hashTree(root)
	if err := os.Symlink("a", filepath.Join(root, "l")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	withLink := hashTree(root)
	if withLink == plain {
		t.Fatal("adding a symlink must change the hash")
	}
	os.Remove(filepath.Join(root, "l"))
	os.Symlink("b", filepath.Join(root, "l"))
	if hashTree(root) == withLink {
		t.Fatal("retargeting a symlink must change the hash")
	}
	// The target's content is not read: changing it leaves the hash alone.
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("one"), 0o600)
	os.Remove(filepath.Join(root, "l"))
	os.Symlink(outside, filepath.Join(root, "l"))
	before := hashTree(root)
	os.WriteFile(outside, []byte("two"), 0o600)
	if hashTree(root) != before {
		t.Fatal("a symlink's target content must not feed the hash")
	}
}
