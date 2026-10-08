package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "f")
	for _, data := range []string{"first", "second, longer"} {
		if err := Write(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(path); string(got) != data {
			t.Fatalf("read %q", got)
		}
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", st.Mode().Perm())
	}
	if left, _ := os.ReadDir(filepath.Dir(path)); len(left) != 1 {
		t.Fatalf("%d entries left", len(left))
	}
}

func TestWriteErrors(t *testing.T) {
	parent := t.TempDir()
	// A non-empty directory where the file should go makes the rename fail.
	dst := filepath.Join(parent, "dst")
	os.MkdirAll(filepath.Join(dst, "occupied"), 0o700)
	if err := Write(dst, []byte("x"), 0o600); err == nil {
		t.Fatal("replaced a directory")
	}
	if left, _ := os.ReadDir(parent); len(left) != 1 {
		t.Fatalf("temporary file left behind: %d entries", len(left))
	}
	blocker := filepath.Join(parent, "file")
	os.WriteFile(blocker, nil, 0o600)
	if err := Write(filepath.Join(blocker, "f"), nil, 0o600); err == nil {
		t.Fatal("wrote under a regular file")
	}
	if os.Geteuid() != 0 {
		ro := filepath.Join(parent, "ro")
		os.Mkdir(ro, 0o500)
		if err := Write(filepath.Join(ro, "f"), nil, 0o600); err == nil {
			t.Fatal("wrote into a read-only directory")
		}
	}
}
