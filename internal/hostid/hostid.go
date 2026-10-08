// Package hostid keeps the secret the sensor's pairing is bound to: 32
// random bytes in a root-only file. It stands in for the DMI identity the
// reference uses (see docs/DESIGN.md, "Pairing identity"). Losing the
// file orphans the pairing, so it belongs in backups.
package hostid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultPath is where fpd and fpctl look for the secret.
const DefaultPath = "/var/lib/fpd/host-secret"

// Size is the secret's length in bytes.
const Size = 32

// Load reads the secret at path. It refuses a file other users can read
// or write, since the secret unlocks the host's pairing key.
func Load(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("host secret: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("host secret: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("host secret %s: mode %04o, want no group or other access", path, st.Mode().Perm())
	}
	b := make([]byte, Size+1)
	n, err := f.Read(b)
	if err != nil {
		return nil, fmt.Errorf("host secret %s: %w", path, err)
	}
	if n != Size {
		return nil, fmt.Errorf("host secret %s: %d bytes, want %d", path, n, Size)
	}
	return b[:Size], nil
}

// LoadOrCreate loads the secret, creating it (and its directory, mode
// 0700) when there is none yet. created reports which happened. An
// existing secret is never replaced.
func LoadOrCreate(path string) (secret []byte, created bool, err error) {
	secret, err = Load(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return secret, false, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("host secret: %w", err)
	}
	secret = make([]byte, Size)
	rand.Read(secret)
	if err := writeNew(path, secret); err != nil {
		return nil, false, err
	}
	return secret, true, nil
}

// writeNew creates path exclusively and makes the new file durable
// before returning, so a crash cannot leave a pairing whose secret never
// reached the disk.
func writeNew(path string, secret []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("host secret: %w", err)
	}
	if _, err := f.Write(secret); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("host secret %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("host secret %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("host secret %s: %w", path, err)
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("host secret: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("host secret: sync %s: %w", filepath.Dir(path), err)
	}
	return nil
}
