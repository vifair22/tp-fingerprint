package hostid

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fpd", "host-secret")
	s1, created, err := LoadOrCreate(path)
	if err != nil || !created || len(s1) != Size {
		t.Fatalf("first call: %x, %v, %v", s1, created, err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %04o", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %04o", dst.Mode().Perm())
	}
	s2, created, err := LoadOrCreate(path)
	if err != nil || created || !bytes.Equal(s1, s2) {
		t.Fatalf("second call: %v, %v; secret changed: %v", created, err, !bytes.Equal(s1, s2))
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name string
		path string
		want string
	}{
		{"missing", filepath.Join(dir, "nope"), "no such file"},
		{"group readable", write("g", make([]byte, Size), 0o640), "no group or other"},
		{"short", write("s", make([]byte, 5), 0o600), "5 bytes"},
		{"long", write("l", make([]byte, 40), 0o600), "33 bytes"},
		{"empty", write("e", nil, 0o600), "EOF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	// A bad existing file is reported, never replaced.
	bad := filepath.Join(dir, "s")
	if _, _, err := LoadOrCreate(bad); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadOrCreate over a bad file: %v", err)
	}
}

func TestLoadOrCreateUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, _, err := LoadOrCreate(filepath.Join(dir, "sub", "secret")); err == nil {
		t.Fatal("created under an unwritable directory")
	}
	if _, _, err := LoadOrCreate(filepath.Join(dir, "secret")); err == nil {
		t.Fatal("created in an unwritable directory")
	}
}
