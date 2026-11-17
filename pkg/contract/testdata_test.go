package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTestdataContracts parses testdata/good (must load) and testdata/bad (must
// be rejected with the error named on the file's leading "# want:" line). The
// bad cases are the values schemas/contract.schema.json rejects, which the
// decoder must reject too.
func TestTestdataContracts(t *testing.T) {
	good, _ := filepath.Glob("testdata/good/*.yaml")
	bad, _ := filepath.Glob("testdata/bad/*.yaml")
	if len(good) == 0 || len(bad) == 0 {
		t.Fatal("no testdata contracts")
	}
	for _, f := range good {
		t.Run("good/"+filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data); err != nil {
				t.Fatalf("want ok, got %v", err)
			}
		})
	}
	for _, f := range bad {
		t.Run("bad/"+filepath.Base(f), func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			first, _, _ := strings.Cut(string(data), "\n")
			want, ok := strings.CutPrefix(first, "# want: ")
			if !ok {
				t.Fatal(`bad testdata must start with "# want: <error substring>"`)
			}
			_, err = Parse(data)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", want)
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("want error containing %q, got %v", want, err)
			}
		})
	}
}
