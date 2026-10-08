package fwfetch

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sum(b []byte) string {
	h := sha512.Sum512(b)
	return hex.EncodeToString(h[:])
}

func TestPinnedHash(t *testing.T) {
	if len(InstallerSHA512) != 128 {
		t.Fatalf("pinned hash is %d hex digits", len(InstallerSHA512))
	}
}

func TestDownload(t *testing.T) {
	body := []byte("pretend installer")
	var gotReferer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReferer = r.Header.Get("Referer")
		switch r.URL.Path {
		case "/ok":
			w.Write(body)
		case "/huge":
			w.Write(make([]byte, maxInstaller+1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	dir := t.TempDir()
	p, err := Download(ctx, srv.Client(), srv.URL+"/ok", sum(body), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(body) {
		t.Fatalf("downloaded %q", got)
	}
	if gotReferer != srv.URL+"/ok" {
		t.Errorf("referer %q", gotReferer)
	}
	if err := Verify(p, sum(body)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path, want string
		err              error
	}{
		{"hash mismatch", "/ok", sum([]byte("other")), ErrHashMismatch},
		{"http error", "/missing", sum(body), nil},
		{"too large", "/huge", sum(body), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			_, err := Download(ctx, srv.Client(), srv.URL+tt.path, tt.want, d)
			if err == nil || (tt.err != nil && !errors.Is(err, tt.err)) {
				t.Fatalf("err = %v", err)
			}
			if left, _ := os.ReadDir(d); len(left) != 0 {
				t.Fatalf("left %d files behind", len(left))
			}
		})
	}
	if _, err := Download(ctx, srv.Client(), "http://127.0.0.1:1/x", sum(body), dir); err == nil {
		t.Fatal("download from a closed port succeeded")
	}
	if _, err := Download(ctx, srv.Client(), "::bad", sum(body), dir); err == nil {
		t.Fatal("bad url accepted")
	}
	if _, err := Download(ctx, srv.Client(), srv.URL+"/ok", sum(body), filepath.Join(dir, "nope")); err == nil {
		t.Fatal("download into a missing directory succeeded")
	}
}

func TestVerifyErrors(t *testing.T) {
	if err := Verify(filepath.Join(t.TempDir(), "nope"), ""); err == nil {
		t.Fatal("missing file verified")
	}
	if err := Verify(t.TempDir(), ""); err == nil {
		t.Fatal("directory verified")
	}
}

// fakeInnoextract writes a script that behaves like innoextract for the
// arguments Extract passes: it creates the requested file under a nested
// app/ path in the output directory, unless told to fail or to omit it.
func fakeInnoextract(t *testing.T, mode string) string {
	t.Helper()
	script := `#!/bin/bash
out= inc=
while [ $# -gt 0 ]; do
  case $1 in
    --output-dir) out=$2; shift ;;
    --include) inc=$2; shift ;;
  esac
  shift
done
case "` + mode + `" in
  fail) echo "not an Inno Setup installer" >&2; exit 1 ;;
  omit) mkdir -p "$out/app"; exit 0 ;;
esac
mkdir -p "$out/app/sub"
printf 'firmware for %s' "$inc" > "$out/app/sub/$inc"
`
	p := filepath.Join(t.TempDir(), "innoextract")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractAndInstall(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path, cleanup, err := Extract(ctx, fakeInnoextract(t, "ok"), "installer.exe", "fw.xpfwext", dir)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "fpd", "fw.xpfwext")
	if err := Install(path, dst); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if got, _ := os.ReadFile(dst); string(got) != "firmware for fw.xpfwext" {
		t.Fatalf("installed %q", got)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatal("cleanup left the extraction behind")
	}
	if left, _ := os.ReadDir(filepath.Dir(dst)); len(left) != 1 {
		t.Fatalf("install left %d entries", len(left))
	}
}

func TestExtractFailures(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name, innoextract, want string
	}{
		{"innoextract fails", fakeInnoextract(t, "fail"), "not an Inno Setup installer"},
		{"file missing", fakeInnoextract(t, "omit"), "not in the installer"},
		{"no innoextract", filepath.Join(t.TempDir(), "absent"), "innoextract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			_, _, err := Extract(ctx, tt.innoextract, "installer.exe", "fw.xpfwext", dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatal("extraction directory left behind")
			}
		})
	}
	if _, _, err := Extract(ctx, "true", "i", "n", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("extract into a missing directory succeeded")
	}
}

func TestInstallErrors(t *testing.T) {
	if err := Install(filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "x")); err == nil {
		t.Fatal("installed a missing file")
	}
	src := filepath.Join(t.TempDir(), "src")
	os.WriteFile(src, []byte("x"), 0o600)
	// dst is a non-empty directory, so the final rename fails.
	parent := t.TempDir()
	dst := filepath.Join(parent, "dst")
	os.MkdirAll(filepath.Join(dst, "occupied"), 0o700)
	if err := Install(src, dst); err == nil {
		t.Fatal("installed over a directory")
	}
	if left, _ := os.ReadDir(parent); len(left) != 1 {
		t.Fatalf("temporary file left behind: %d entries", len(left))
	}
}
