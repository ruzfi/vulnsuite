package engine

import (
	"archive/tar"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

type entry struct {
	name, link, data string
	typ              byte
}

func tarStream(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: 0o644}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	return &buf
}

// The archive comes from the container: nothing in it may name a file outside
// the directory, be followed, or grow past the cap.
func TestDirFilesFromTarIsStrict(t *testing.T) {
	r := tarStream(t,
		entry{name: "asan/", typ: tar.TypeDir},
		entry{name: "asan/a", data: "hello world", typ: tar.TypeReg},
		entry{name: "asan/a", data: "second a", typ: tar.TypeReg},           // duplicate: first wins
		entry{name: "asan/../escape", data: "x", typ: tar.TypeReg},          // traversal
		entry{name: "../escape", data: "x", typ: tar.TypeReg},               // outside the root
		entry{name: "/etc/passwd", data: "x", typ: tar.TypeReg},             // absolute
		entry{name: "asan/./dot", data: "x", typ: tar.TypeReg},              // not a single element
		entry{name: "asan/sub/nested", data: "x", typ: tar.TypeReg},         // below a subdirectory
		entry{name: "asan/sub/", typ: tar.TypeDir},                          // a subdirectory
		entry{name: "asanx/sibling", data: "x", typ: tar.TypeReg},           // a sibling sharing the prefix
		entry{name: "asan/link", link: "/etc/shadow", typ: tar.TypeSymlink}, // never followed
		entry{name: "asan/fifo", typ: tar.TypeFifo},
		entry{name: "asan/dev", typ: tar.TypeChar},
		entry{name: "asan/hard", link: "asan/a", typ: tar.TypeLink},        // a second name for a
		entry{name: "asan/hardout", link: "etc/shadow", typ: tar.TypeLink}, // a link to outside
		entry{name: "asan/..", data: "x", typ: tar.TypeReg},
		entry{name: "asan/empty", typ: tar.TypeReg},
	)
	got, err := DirFilesFromTar(r, "asan", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d files %v, want a, hard and empty only", len(got), got)
	}
	for _, n := range []string{"a", "hard"} {
		if f := got[n]; f.Size != 11 || string(f.Data) != "hello" || !f.Truncated() {
			t.Errorf("%s = size %d %q truncated %v; want the first a's 11 bytes cut to hello", n, f.Size, f.Data, f.Truncated())
		}
	}
	if f, ok := got["empty"]; !ok || f.Size != 0 || len(f.Data) != 0 || f.Truncated() {
		t.Errorf("empty = %+v, %v", f, ok)
	}
}

func TestDirFilesFromTarRootAndLimits(t *testing.T) {
	// dockerd names the root directory's entries "/<name>".
	got, err := DirFilesFromTar(tarStream(t, entry{name: "/", typ: tar.TypeDir}, entry{name: "/top", data: "t", typ: tar.TypeReg},
		entry{name: "/bin/sh", data: "x", typ: tar.TypeReg}), "/", -1)
	if err != nil || len(got) != 1 || got["top"].Size != 1 || len(got["top"].Data) != 0 {
		t.Fatalf("root = %v, %v; want top with its size and, for a negative cap, no data", got, err)
	}

	many := make([]entry, 0, MaxDirFiles+1)
	for i := 0; i <= MaxDirFiles; i++ {
		many = append(many, entry{name: fmt.Sprintf("d/f%d", i), typ: tar.TypeReg})
	}
	if _, err := DirFilesFromTar(tarStream(t, many...), "d", 1); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("%d files = %v; want an error", MaxDirFiles+1, err)
	}
	if got, err := DirFilesFromTar(tarStream(t, many[:MaxDirFiles]...), "d", 1); err != nil || len(got) != MaxDirFiles {
		t.Errorf("%d files = %d, %v; want all of them", MaxDirFiles, len(got), err)
	}

	// A stream cut short inside a file is an error, not a short file.
	full := tarStream(t, entry{name: "d/a", data: strings.Repeat("x", 4096), typ: tar.TypeReg}).Bytes()
	if _, err := DirFilesFromTar(bytes.NewReader(full[:1024]), "d", 8192); err == nil {
		t.Error("a truncated archive must be an error")
	}
}

// The per-file cap times MaxDirFiles is no memory bound: the total is
// (#131). Hard links count too, as they are copied.
func TestDirFilesFromTarTotalCap(t *testing.T) {
	chunk := strings.Repeat("a", 1<<20)
	n := MaxDirBytes>>20 + 1
	var es []entry
	for i := 0; i < n; i++ {
		es = append(es, entry{name: fmt.Sprintf("d/f%03d", i), data: chunk, typ: tar.TypeReg})
	}
	if _, err := DirFilesFromTar(tarStream(t, es...), "d", 1<<20); err == nil || !strings.Contains(err.Error(), "MiB") {
		t.Fatalf("%d MiB = %v; want the total cap", n, err)
	}
	if got, err := DirFilesFromTar(tarStream(t, es[:n-1]...), "d", 1<<20); err != nil || len(got) != n-1 {
		t.Fatalf("%d MiB = %d files, %v; want all of them", n-1, len(got), err)
	}
	links := []entry{es[0]}
	for i := 1; i < n; i++ {
		links = append(links, entry{name: fmt.Sprintf("d/l%03d", i), link: "d/f000", typ: tar.TypeLink})
	}
	if _, err := DirFilesFromTar(tarStream(t, links...), "d", 1<<20); err == nil {
		t.Fatal("hard links to one big file must count toward the cap")
	}
}
