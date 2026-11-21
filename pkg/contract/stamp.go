package contract

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	metadataKeyRe = regexp.MustCompile(`^metadata:[ \t]*(#.*)?$`)
	plainScalarRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]*$`)
)

// Stamp records vo in the contract's metadata.verified_on and marks it
// verification: verified. vo replaces the run recorded for the same host and
// platform and keeps the runs on others: one run is written as a mapping
// (the form vulnsuite v0.5.0 reads), several as a list. It edits only those
// lines of data, so the rest of a hand-written contract (comments, quoting,
// key order) is left as it was, and it re-parses the result to prove that
// nothing else changed. It needs metadata to be a block mapping (not a
// {flow} one).
func Stamp(data []byte, vo VerifiedOn) ([]byte, error) {
	before, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := vo.check("verified_on"); err != nil {
		return nil, err
	}
	want := before.Metadata.VerifiedOn.With(vo)
	nl := "\n"
	if strings.Contains(string(data), "\r\n") {
		nl = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	start := -1
	for i, l := range lines {
		if metadataKeyRe.MatchString(l) {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, errors.New("metadata is not a block mapping (metadata: on a line of its own); add verified_on by hand")
	}
	// The block runs until the next line that is content at column 0.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if isContent(lines[i]) && indentOf(lines[i]) == 0 {
			end = i
			break
		}
	}
	child := -1
	for i := start + 1; i < end; i++ {
		if isContent(lines[i]) {
			child = indentOf(lines[i])
			break
		}
	}
	if child <= 0 {
		return nil, errors.New("metadata has no keys")
	}
	pad := strings.Repeat(" ", child)
	keyAt := func(i int) string {
		l := lines[i]
		if !isContent(l) || indentOf(l) != child {
			return ""
		}
		k, _, ok := strings.Cut(l[child:], ":")
		if !ok {
			return ""
		}
		return strings.TrimSpace(k)
	}

	// verification may come before or after verified_on: rewrite it first,
	// in place. A comment on its line goes with it: it says why the target
	// was unverified, which the stamp makes stale.
	for i := start + 1; i < end; i++ {
		if keyAt(i) == "verification" {
			lines[i] = pad + "verification: " + VerificationVerified
		}
	}
	block := renderVerifiedRuns(want, pad, strings.Repeat(" ", child))
	var out []string
	replaced := false
	for i := start + 1; i < end; i++ {
		switch keyAt(i) {
		case "verified_on":
			// Its value runs until the next line that is content at the
			// key's own indentation or less, except the items of a list
			// written at the key's indentation; trailing blank and
			// shallower comment lines stay where they are.
			j := i + 1
			for j < end && !(isContent(lines[j]) && indentOf(lines[j]) <= child && !isItemAt(lines[j], child)) {
				j++
			}
			for j > i+1 && !isDeeper(lines[j-1], child) && !isItemAt(lines[j-1], child) {
				j--
			}
			out = append(append(append(out, lines[:i]...), block...), lines[j:]...)
			replaced = true
		}
		if replaced {
			break
		}
	}
	if !replaced {
		last := start
		for i := start + 1; i < end; i++ {
			if isContent(lines[i]) {
				last = i
			}
		}
		out = append(append(append(out, lines[:last+1]...), block...), lines[last+1:]...)
	}
	result := []byte(strings.Join(out, nl))

	// Prove the edit: it parses, carries exactly vo and verified, and every
	// other field is unchanged.
	after, err := Parse(result)
	if err != nil {
		return nil, fmt.Errorf("the stamped contract does not parse (%v); add verified_on by hand", err)
	}
	if !reflect.DeepEqual(after.Metadata.VerifiedOn, want) {
		return nil, errors.New("could not place verified_on in metadata; add it by hand")
	}
	if after.IsUnverified() {
		return nil, errors.New("could not rewrite metadata.verification; set it to verified by hand")
	}
	before.Metadata.Verification, after.Metadata.Verification = "", ""
	before.Metadata.VerifiedOn, after.Metadata.VerifiedOn = nil, nil
	if !reflect.DeepEqual(before, after) {
		return nil, errors.New("stamping would change more than metadata.verification and verified_on; add verified_on by hand")
	}
	return result, nil
}

// StampFile applies Stamp to the contract at path, replacing the file
// atomically and keeping its mode. A symlinked contract is written through
// the link.
func StampFile(path string, vo VerifiedOn) error {
	return stampFile(path, vo, nil)
}

// StampSource stamps the file c was loaded from (c.SourcePath), after
// checking that it still holds the contract that ran: apart from
// metadata.verification and verified_on, which another stamp may have
// written meanwhile, it must parse to the same contract as c.SourceData,
// the bytes the loader read. A contract with no SourceData is stamped
// unchecked, as StampFile does.
func StampSource(c *Contract, vo VerifiedOn) error {
	return stampFile(c.SourcePath, vo, c.SourceData)
}

func stampFile(path string, vo VerifiedOn, loaded []byte) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	unlock, err := lockStamp(real)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer unlock()
	data, err := os.ReadFile(real)
	if err != nil {
		return err
	}
	if loaded != nil && !bytes.Equal(data, loaded) {
		if err := sameButEvidence(loaded, data); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	out, err := Stamp(data, vo)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(real), ".stamp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), st.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), real)
}

// sameButEvidence reports, as an error, that now is not the contract loaded
// was, comparing everything but metadata.verification and verified_on.
func sameButEvidence(loaded, now []byte) error {
	const changed = "the contract changed since it was loaded, so the run does not prove it; run stamp again"
	a, err := Parse(loaded)
	if err != nil {
		return errors.New(changed)
	}
	b, err := Parse(now)
	if err != nil {
		return fmt.Errorf("%s (it no longer parses: %v)", changed, err)
	}
	a.Metadata.Verification, b.Metadata.Verification = "", ""
	a.Metadata.VerifiedOn, b.Metadata.VerifiedOn = nil, nil
	if !reflect.DeepEqual(a, b) {
		return errors.New(changed)
	}
	return nil
}

// stampLockWait is how long a stamp waits for another one writing the same
// file; a lock older than stampLockStale was left by a stamp that died.
var (
	stampLockWait  = 10 * time.Second
	stampLockStale = time.Minute
)

// lockStamp takes the lock file next to path, so that two stamps of one
// file (say, on two hosts sharing a checkout) cannot both read it and the
// later write lose the earlier's run.
func lockStamp(path string) (func(), error) {
	lock := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".stamp-lock")
	deadline := time.Now().Add(stampLockWait)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			return func() { os.Remove(lock) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(lock); serr == nil && time.Since(st.ModTime()) > stampLockStale {
			os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another stamp is writing this file (remove %s if none is)", lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// renderVerifiedRuns writes the verified_on key at pad, its content one step
// deeper: a mapping for one run, a list of mappings for several.
func renderVerifiedRuns(runs VerifiedRuns, pad, step string) []string {
	out := []string{pad + "verified_on:"}
	inner := pad + step
	if len(runs) == 1 {
		return append(out, renderRun(runs[0], inner, inner)...)
	}
	for _, vo := range runs {
		out = append(out, renderRun(vo, inner+"- ", inner+"  ")...)
	}
	return out
}

// renderRun writes one run's fields, the first prefixed with first and the
// rest with rest.
func renderRun(vo VerifiedOn, first, rest string) []string {
	out := []string{
		first + "date: " + strconv.Quote(vo.Date),
		rest + "vulnsuite: " + yamlScalar(vo.Vulnsuite),
		rest + "host: " + yamlScalar(vo.Host),
	}
	if vo.Platform != "" {
		out = append(out, rest+"platform: "+yamlScalar(vo.Platform))
	}
	if len(vo.CPUFlags) > 0 {
		out = append(out, rest+"cpu_flags: "+flowList(vo.CPUFlags))
	}
	return append(out, rest+"states: "+flowList(vo.States))
}

// yamlScalar writes s plain when that cannot be misread, else double-quoted
// (a Go-quoted string is a valid YAML double-quoted scalar).
func yamlScalar(s string) string {
	if plainScalarRe.MatchString(s) && !strings.ContainsAny(s[:1], "0123456789") {
		return s
	}
	return strconv.Quote(s)
}

func flowList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = yamlScalar(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// isContent reports whether a line holds YAML content (not blank, not only a
// comment).
func isContent(l string) bool {
	t := strings.TrimSpace(l)
	return t != "" && !strings.HasPrefix(t, "#")
}

// isItemAt reports whether l is a list item ("- ...") indented exactly col.
func isItemAt(l string, col int) bool {
	return indentOf(l) == col && (strings.HasPrefix(l[col:], "- ") || strings.TrimSpace(l[col:]) == "-")
}

// isDeeper reports whether l is a content or comment line indented past col.
func isDeeper(l string, col int) bool {
	return strings.TrimSpace(l) != "" && indentOf(l) > col
}
