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

	"git.airies.net/vifair22/tp-fingerprint/internal/promptled"
	"git.airies.net/vifair22/tp-fingerprint/internal/proto"
	"git.airies.net/vifair22/tp-fingerprint/internal/server"
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

// promptingReader prompts, then reports what the LED's trigger was while
// it waited.
type promptingReader struct {
	stubReader
	dir  string
	seen []string
}

func (p *promptingReader) look(prompt func()) {
	prompt()
	b, _ := os.ReadFile(filepath.Join(p.dir, "trigger"))
	p.seen = append(p.seen, string(b))
}

func (p *promptingReader) Verify(_ context.Context, _ uint32, prompt, _ func()) (bool, error) {
	p.look(prompt)
	return true, nil
}

func (p *promptingReader) Identify(_ context.Context, prompt, _ func()) (server.Enrolled, bool, error) {
	p.look(prompt)
	return server.Enrolled{}, true, nil
}

func (p *promptingReader) Enroll(_ context.Context, _ uint32, _ uint16, prompt func(), _ func(int, error)) error {
	p.look(prompt)
	return nil
}

func TestLEDReaderFlashesWhileWaiting(t *testing.T) {
	dir := t.TempDir()
	for name, v := range map[string]string{
		"trigger": "none [chromeos-auto] timer", "delay_on": "", "delay_off": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	led, err := promptled.Open(dir, "", slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	inner := &promptingReader{dir: dir}
	r := ledReader{reader: inner, led: led}
	ctx := context.Background()
	if _, err := r.Verify(ctx, 1000, func() {}, func() {}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Identify(ctx, func() {}, func() {}); err != nil {
		t.Fatal(err)
	}
	if err := r.Enroll(ctx, 1000, 1, func() {}, func(int, error) {}); err != nil {
		t.Fatal(err)
	}
	for i, s := range inner.seen {
		if s != "timer" {
			t.Fatalf("request %d: trigger %q while waiting", i, s)
		}
	}
	if len(inner.seen) != 3 {
		t.Fatalf("%d requests prompted", len(inner.seen))
	}
	b, _ := os.ReadFile(filepath.Join(dir, "trigger"))
	if string(b) != "chromeos-auto" {
		t.Fatalf("trigger %q after the requests", b)
	}
}

func TestRunWithMissingPromptLED(t *testing.T) {
	var out bytes.Buffer
	// The LED is missing, which only warns; the socket is a regular file,
	// which stops the run before it serves.
	file := filepath.Join(t.TempDir(), "notasocket")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"--sensor", "crosfp", "--no-dbus", "--socket", file,
		"--prompt-led", filepath.Join(t.TempDir(), "absent")}, &out)
	if code != 1 || !strings.Contains(out.String(), "no prompt LED") {
		t.Fatalf("code %d, log %q", code, out.String())
	}

	// A present LED is taken, and its trigger put back on the way out.
	led := t.TempDir()
	if err := os.WriteFile(filepath.Join(led, "trigger"), []byte("[none] timer"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code = run([]string{"--sensor", "crosfp", "--no-dbus", "--socket", file, "--prompt-led", led}, &out)
	b, _ := os.ReadFile(filepath.Join(led, "trigger"))
	if code != 1 || !strings.Contains(out.String(), "prompt LED") || string(b) != "none" {
		t.Fatalf("code %d, trigger %q, log %q", code, b, out.String())
	}
}
