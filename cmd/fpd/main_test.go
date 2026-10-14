package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
)

type stubReader struct {
	warmErr error
	closed  bool
}

func (*stubReader) Verify(context.Context, uint32, func(), func()) (bool, error) { return true, nil }
func (*stubReader) Identify(context.Context, func(), func()) (server.Enrolled, bool, error) {
	return server.Enrolled{}, false, nil
}
func (*stubReader) Enroll(context.Context, uint32, uint16, func(), func(int, error)) error {
	return nil
}
func (*stubReader) List(uint32) ([]server.Enrolled, error) { return nil, nil }
func (*stubReader) Delete(uint32, uint16) error            { return nil }
func (s *stubReader) Warm() error                          { return s.warmErr }
func (s *stubReader) Close() error                         { s.closed = true; return nil }

func TestServeLifecycle(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "fpd.sock")
	r := &stubReader{warmErr: errors.New("no sensor yet")}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	var started, stopped bool
	bus := func(*slog.Logger, server.Reader, *server.Server) func() {
		started = true
		return func() { stopped = true }
	}
	go func() { done <- serve(ctx, log, sock, r, nil, bus) }()

	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(sock); st.Mode().Perm() != 0o666 {
		t.Errorf("socket mode %04o", st.Mode().Perm())
	}
	proto.Write(c, proto.ReqList, proto.U32s(uint32(os.Getuid())))
	f, err := proto.Read(c)
	if err != nil || f.Type != proto.EvResult {
		t.Fatalf("%+v, %v", f, err)
	}
	c.Close()

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !r.closed {
		t.Error("sensor not shut down")
	}
	if !started || !stopped {
		t.Errorf("D-Bus API started %v, stopped %v", started, stopped)
	}
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Error("socket left behind")
	}
	if !strings.Contains(logs.String(), "sensor not ready") {
		t.Error("warm failure not logged")
	}
}

func TestListen(t *testing.T) {
	dir := t.TempDir()
	// A stale socket from an earlier run is replaced.
	sock := filepath.Join(dir, "s")
	old, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	ln, err := listen(sock)
	if err != nil {
		t.Fatalf("over a stale socket: %v", err)
	}
	ln.Close()
	// Anything else is left alone.
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o600)
	if _, err := listen(file); err == nil {
		t.Fatal("replaced a regular file")
	}
	if _, err := listen(filepath.Join(file, "s")); err == nil {
		t.Fatal("listened under a regular file")
	}
	if err := serve(context.Background(), slog.New(slog.DiscardHandler), file, &stubReader{}, nil, nil); err == nil {
		t.Fatal("served on a regular file")
	}
}

func TestRunArgs(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--help"}, &out); code != 0 || !strings.Contains(out.String(), "usage: fpd") {
		t.Fatalf("help: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--version"}, &out); code != 0 || !strings.Contains(out.String(), "fpd 0.0.0") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	for _, bad := range [][]string{{"--nope"}, {"extra"}} {
		if code := run(bad, &out); code != 1 {
			t.Fatalf("%v: exit %d", bad, code)
		}
	}
	// A socket that cannot be created stops fpd with an error.
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	if code := run([]string{"--socket", file}, &out); code != 1 {
		t.Fatalf("bad socket: exit %d", code)
	}
}

func TestLookupUID(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	uid, err := lookupUID(me.Username)
	if err != nil || strconv.FormatUint(uint64(uid), 10) != me.Uid {
		t.Fatalf("%d, %v", uid, err)
	}
	if _, err := lookupUID("no-such-user-at-all"); err == nil {
		t.Fatal("found a missing user")
	}
}

// Without a reachable system bus, fpd carries on without the D-Bus API.
func TestStartFprintWithoutABus(t *testing.T) {
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/bus")
	var logs bytes.Buffer
	stop := startFprint(slog.New(slog.NewTextHandler(&logs, nil)), &stubReader{}, nil)
	stop()
	if !strings.Contains(logs.String(), "not serving the fprintd D-Bus API") {
		t.Fatalf("log %q", logs.String())
	}
}

func TestChooseSensor(t *testing.T) {
	tests := []struct {
		flag    string
		present bool
		want    string
		bad     bool
	}{
		{"auto", true, "crosfp", false},
		{"auto", false, "validity", false},
		{"validity", true, "validity", false},
		{"crosfp", false, "crosfp", false},
		{"nonsense", true, "", true},
	}
	for _, tt := range tests {
		got, err := chooseSensor(tt.flag, tt.present)
		if (err != nil) != tt.bad || got != tt.want {
			t.Errorf("chooseSensor(%q, %v) = %q, %v", tt.flag, tt.present, got, err)
		}
	}
}
