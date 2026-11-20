package contract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var (
	metadataKeyRe = regexp.MustCompile(`^metadata:[ \t]*(#.*)?$`)
	plainScalarRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]*$`)
)

// Stamp records vo as the contract's metadata.verified_on and marks it
// verification: verified. It edits only those lines of data, so the rest of
// a hand-written contract (comments, quoting, key order) is left as it was,
// and it re-parses the result to prove that nothing else changed. It needs
// metadata to be a block mapping (not a {flow} one).
func Stamp(data []byte, vo VerifiedOn) ([]byte, error) {
	before, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := vo.check(); err != nil {
		return nil, err
	}
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

	block := renderVerifiedOn(vo, pad, strings.Repeat(" ", 2*child))
	var out []string
	replaced := false
	for i := start + 1; i < end; i++ {
		switch keyAt(i) {
		case "verification":
			lines[i] = pad + "verification: " + VerificationVerified
		case "verified_on":
			// Its value runs until the next line that is content at the
			// key's own indentation or less; trailing blank and shallower
			// comment lines stay where they are.
			j := i + 1
			for j < end && !(isContent(lines[j]) && indentOf(lines[j]) <= child) {
				j++
			}
			for j > i+1 && !isDeeper(lines[j-1], child) {
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
	if after.Metadata.VerifiedOn == nil || !reflect.DeepEqual(*after.Metadata.VerifiedOn, vo) {
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
// atomically and keeping its mode.
func StampFile(path string, vo VerifiedOn) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, err := Stamp(data, vo)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stamp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), st.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func renderVerifiedOn(vo VerifiedOn, pad, pad2 string) []string {
	out := []string{
		pad + "verified_on:",
		pad2 + "date: " + strconv.Quote(vo.Date),
		pad2 + "vulnsuite: " + yamlScalar(vo.Vulnsuite),
		pad2 + "host: " + yamlScalar(vo.Host),
	}
	if vo.Platform != "" {
		out = append(out, pad2+"platform: "+yamlScalar(vo.Platform))
	}
	if len(vo.CPUFlags) > 0 {
		out = append(out, pad2+"cpu_flags: "+flowList(vo.CPUFlags))
	}
	return append(out, pad2+"states: "+flowList(vo.States))
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

// isDeeper reports whether l is a content or comment line indented past col.
func isDeeper(l string, col int) bool {
	return strings.TrimSpace(l) != "" && indentOf(l) > col
}
