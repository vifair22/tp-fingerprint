package crosfp

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenRefusesANonDevice(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-device")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); !errors.Is(err, syscall.ENOTTY) {
		t.Fatalf("err %v, want ENOTTY from the event mask", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err %v, want not exist", err)
	}
}

func TestCommandOnANonDevice(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{f: f}
	defer d.Close()
	if _, err := d.Command(cmdFPInfo, 2, []byte{1, 2}, 36); !errors.Is(err, syscall.ENOTTY) {
		t.Fatalf("err %v, want ENOTTY", err)
	}
	if _, err := d.Command(cmdFPInfo, 2, nil, -1); err == nil {
		t.Fatal("negative size accepted")
	}
}

func TestNextEventOverAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	d := &Device{f: r}
	defer d.Close()
	// A non-fingerprint event first, which is skipped, then a fingerprint
	// one.
	if _, err := w.Write([]byte{1, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	ev := make([]byte, 5)
	ev[0] = mkbpFingerprint
	binary.LittleEndian.PutUint32(ev[1:], uint32(EventFingerUp))
	go func() {
		time.Sleep(300 * time.Millisecond) // past one read slice
		_, _ = w.Write(ev)
	}()
	e, err := d.NextEvent(context.Background())
	if err != nil || e != EventFingerUp {
		t.Fatalf("event %#x err %v", e, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.NextEvent(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want cancelled", err)
	}
	w.Close()
	if _, err := d.NextEvent(context.Background()); err == nil {
		t.Fatal("read past EOF succeeded")
	}
}
