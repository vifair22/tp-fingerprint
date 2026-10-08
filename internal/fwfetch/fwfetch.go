// Package fwfetch gets the sensor's firmware extension out of Lenovo's
// Windows driver package. The firmware is proprietary, so it is fetched on
// the machine that uses it and never packaged or published; the download
// is pinned by SHA-512 to the package python-validity pins.
package fwfetch

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"git.airies.net/vifair22/t480-fingerprint/internal/atomicfile"
)

// The driver package and its pinned hash, from python-validity's
// firmware_tables.py (DEV_9a).
const (
	InstallerURL    = "https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe"
	InstallerSHA512 = "a4a4e6058b1ea8ab721953d2cfd775a1e7bc589863d160e5ebbb90344858f147" +
		"d695103677a8df0b2de0c95345df108bda97196245b067f45630038fb7c807cd"
)

// FirmwareSHA256 pins the firmware file extracted from that package
// (FirmwareVersion 6.07.0164, 218482 bytes), recorded on its first
// extraction on 2026-10-07.
const FirmwareSHA256 = "ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1"

// maxInstaller bounds the download; the real package is a few MiB.
const maxInstaller = 64 << 20

// ErrHashMismatch means the installer is not the pinned one.
var ErrHashMismatch = errors.New("installer does not match the pinned SHA-512")

// Download fetches url into a new file in dir and returns its path. The
// file is removed unless its SHA-512 is want.
func Download(ctx context.Context, client *http.Client, url, want, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// Lenovo's CDN has refused requests without these; the reference sends
	// the same pair.
	req.Header.Set("Referer", url)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux)")
	rsp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", url, rsp.Status)
	}
	f, err := os.CreateTemp(dir, "installer-*.exe")
	if err != nil {
		return "", err
	}
	h := sha512.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(rsp.Body, maxInstaller+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxInstaller {
		err = fmt.Errorf("download: larger than %d bytes", maxInstaller)
	}
	if err == nil {
		err = checkHash(h, want)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Verify checks a local copy of the installer against want.
func Verify(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return checkHash(h, want)
}

func checkHash(h hash.Hash, want string) error {
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: got %s", ErrHashMismatch, got)
	}
	return nil
}

// Extract runs innoextract on installer, pulling out only the file called
// name, into a temporary directory under dir, and returns the file's path
// there. cleanup removes the whole extraction; call it once the file has
// been installed.
func Extract(ctx context.Context, innoextract, installer, name, dir string) (path string, cleanup func(), err error) {
	out, err := os.MkdirTemp(dir, "extract-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(out) }
	cmd := exec.CommandContext(ctx, innoextract,
		"--silent", "--output-dir", out, "--include", name, "--collisions", "overwrite", installer)
	if msg, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("innoextract: %w: %s", err, msg)
	}
	// The file sits somewhere under Inno Setup's path layout; find it
	// rather than hardcode that layout.
	err = filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == name {
			path = p
			return fs.SkipAll
		}
		return nil
	})
	if err == nil && path == "" {
		err = fmt.Errorf("innoextract: %s is not in the installer", name)
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// Install copies src to dst atomically, readable by its owner only (the
// firmware is proprietary and stays on this machine).
func Install(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicfile.Write(dst, data, 0o600)
}
