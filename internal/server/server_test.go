package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
)

// fakeReader scripts the sensor: each Verify/Identify consumes the next
// outcome.
type fakeReader struct {
	mu       sync.Mutex
	outcomes []outcome
	enrolled map[uint32][]uint16
	block    chan struct{} // if set, Verify waits on it (or ctx)
	calls    int
}

type outcome struct {
	match    bool
	who      uint32
	badScans int
	err      error
}

func (f *fakeReader) next() outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.outcomes) == 0 {
		return outcome{}
	}
	o := f.outcomes[0]
	f.outcomes = f.outcomes[1:]
	return o
}

func (f *fakeReader) Verify(ctx context.Context, uid uint32, prompt, retry func()) (bool, error) {
	if len(f.enrolled[uid]) == 0 {
		return false, ErrNotEnrolled
	}
	prompt()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	o := f.next()
	for range o.badScans {
		retry()
	}
	return o.match, o.err
}

func (f *fakeReader) Identify(ctx context.Context, prompt, retry func()) (Enrolled, bool, error) {
	prompt()
	o := f.next()
	return Enrolled{UID: o.who, Subtype: 2}, o.match, o.err
}

func (f *fakeReader) Enroll(ctx context.Context, uid uint32, subtype uint16, prompt func(), progress func(int, error)) error {
	for _, s := range f.enrolled[uid] {
		if s == subtype {
			return ErrExists
		}
	}
	prompt()
	progress(1, nil)
	progress(1, errors.New("smudge"))
	progress(2, nil)
	if f.enrolled == nil {
		f.enrolled = map[uint32][]uint16{}
	}
	f.enrolled[uid] = append(f.enrolled[uid], subtype)
	return nil
}

func (f *fakeReader) List(uid uint32) ([]Enrolled, error) {
	var out []Enrolled
	for u, subs := range f.enrolled {
		if uid == proto.AllUsers || u == uid {
			for _, s := range subs {
				out = append(out, Enrolled{u, s})
			}
		}
	}
	return out, nil
}

func (f *fakeReader) Delete(uid uint32, subtype uint16) error {
	if len(f.enrolled[uid]) == 0 {
		return ErrNotEnrolled
	}
	delete(f.enrolled, uid)
	return nil
}

// harness runs a Server on a socketpair per request, with a chosen peer.
type harness struct {
	s      *Server
	r      *fakeReader
	remote bool
}

func newHarness(r *fakeReader) *harness {
	h := &harness{r: r}
	h.s = New(r, slog.New(slog.DiscardHandler), func(int32) bool { return h.remote })
	return h
}

// do sends one request as peer and collects every event up to the result.
func (h *harness) do(t *testing.T, peer uint32, typ uint16, payload []byte) []proto.Frame {
	t.Helper()
	client, server := net.Pipe()
	h.s.peer = func(net.Conn) (Peer, error) { return Peer{UID: peer, PID: 42}, nil }
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		h.s.handle(context.Background(), server)
	}()
	if err := proto.Write(client, typ, payload); err != nil {
		t.Fatal(err)
	}
	var frames []proto.Frame
	for {
		f, err := proto.Read(client)
		if err != nil {
			t.Fatalf("after %v: %v", frames, err)
		}
		frames = append(frames, f)
		if f.Type == proto.EvResult {
			break
		}
	}
	client.Close()
	<-done
	return frames
}

func result(t *testing.T, fs []proto.Frame) uint32 {
	t.Helper()
	v, err := fs[len(fs)-1].Fields(4)
	if err != nil {
		t.Fatal(err)
	}
	return v[0]
}

func types(fs []proto.Frame) []uint16 {
	var out []uint16
	for _, f := range fs {
		out = append(out, f.Type)
	}
	return out
}

func verifyReq(uid, ms, tries uint32) []byte { return proto.U32s(uid, ms, tries) }

func TestVerify(t *testing.T) {
	enrolled := map[uint32][]uint16{1000: {2}}
	tests := []struct {
		name     string
		peer     uint32
		uid      uint32
		tries    uint32
		outcomes []outcome
		remote   bool
		want     uint32
		events   []uint16
	}{
		{"match", 1000, 1000, 3, []outcome{{match: true}}, false, proto.ResultMatch,
			[]uint16{proto.EvPrompt, proto.EvResult}},
		{"root for a user", 0, 1000, 3, []outcome{{match: true}}, false, proto.ResultMatch, nil},
		{"bad scans then match", 1000, 1000, 3, []outcome{{match: true, badScans: 2}}, false, proto.ResultMatch,
			[]uint16{proto.EvPrompt, proto.EvRetry, proto.EvRetry, proto.EvResult}},
		{"no match after the tries", 1000, 1000, 2, []outcome{{}, {}}, false, proto.ResultNoMatch,
			[]uint16{proto.EvPrompt, proto.EvRetry, proto.EvPrompt, proto.EvResult}},
		{"match on the second try", 1000, 1000, 3, []outcome{{}, {match: true}}, false, proto.ResultMatch, nil},
		{"zero tries means one", 1000, 1000, 0, []outcome{{}}, false, proto.ResultNoMatch, nil},
		{"another user's fingers", 1000, 1001, 3, nil, false, proto.ResultDenied, nil},
		{"nothing enrolled", 1001, 1001, 3, nil, false, proto.ResultNotEnrolled, nil},
		{"remote session", 1000, 1000, 3, nil, true, proto.ResultRemote, nil},
		{"sensor unavailable", 1000, 1000, 3, []outcome{{err: ErrUnavailable}}, false, proto.ResultUnavailable, nil},
		{"sensor error", 1000, 1000, 3, []outcome{{err: errors.New("usb")}}, false, proto.ResultError, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(&fakeReader{outcomes: tt.outcomes, enrolled: enrolled})
			h.remote = tt.remote
			fs := h.do(t, tt.peer, proto.ReqVerify, verifyReq(tt.uid, 0, tt.tries))
			if got := result(t, fs); got != tt.want {
				t.Fatalf("result %s, want %s", proto.ResultString(got), proto.ResultString(tt.want))
			}
			if tt.events != nil && !equal(types(fs), tt.events) {
				t.Fatalf("events %x, want %x", types(fs), tt.events)
			}
		})
	}
}

func equal(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestVerifyTimeoutAndBusy(t *testing.T) {
	r := &fakeReader{enrolled: map[uint32][]uint16{1000: {2}}, block: make(chan struct{})}
	h := newHarness(r)
	// A verify that never gets a finger times out.
	fs := h.do(t, 1000, proto.ReqVerify, verifyReq(1000, 50, 1))
	if got := result(t, fs); got != proto.ResultTimeout {
		t.Fatalf("result %s", proto.ResultString(got))
	}

	// While one verify waits, a second request is told the sensor is busy.
	client, server := net.Pipe()
	h.s.peer = func(net.Conn) (Peer, error) { return Peer{UID: 1000}, nil }
	done := make(chan struct{})
	go func() { defer close(done); h.s.handle(context.Background(), server); server.Close() }()
	proto.Write(client, proto.ReqVerify, verifyReq(1000, 10000, 1))
	if f, _ := proto.Read(client); f.Type != proto.EvPrompt {
		t.Fatalf("first event %x", f.Type)
	}
	for _, req := range []struct {
		typ     uint16
		payload []byte
	}{
		{proto.ReqVerify, verifyReq(1000, 0, 1)},
		{proto.ReqList, proto.U32s(1000)},
		{proto.ReqDelete, proto.U16(proto.U32s(1000), 0)},
		{proto.ReqEnroll, proto.U16(proto.U32s(1000), 3)},
	} {
		if got := result(t, h.do(t, 1000, req.typ, req.payload)); got != proto.ResultBusy {
			t.Fatalf("request %x while busy: %s", req.typ, proto.ResultString(got))
		}
	}
	// Hanging up cancels the scan in progress.
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung-up client's scan was not cancelled")
	}
	r.block = nil
	r.outcomes = []outcome{{match: true}}
	if got := result(t, h.do(t, 1000, proto.ReqVerify, verifyReq(1000, 0, 1))); got != proto.ResultMatch {
		t.Fatalf("after the hang-up: %s", proto.ResultString(got))
	}
}

func TestIdentify(t *testing.T) {
	h := newHarness(&fakeReader{outcomes: []outcome{{match: true, who: 1000}, {}, {err: ErrUnavailable}}})
	fs := h.do(t, 0, proto.ReqIdentify, proto.U32s(0))
	if result(t, fs) != proto.ResultMatch {
		t.Fatal(types(fs))
	}
	v, err := fs[len(fs)-2].Fields(4, 2)
	if err != nil || v[0] != 1000 || v[1] != 2 {
		t.Fatalf("finger %v, %v", v, err)
	}
	for _, want := range []uint32{proto.ResultNoMatch, proto.ResultUnavailable} {
		if got := result(t, h.do(t, 0, proto.ReqIdentify, proto.U32s(0))); got != want {
			t.Fatalf("got %s, want %s", proto.ResultString(got), proto.ResultString(want))
		}
	}
	if got := result(t, h.do(t, 1000, proto.ReqIdentify, proto.U32s(0))); got != proto.ResultDenied {
		t.Fatalf("non-root identify: %s", proto.ResultString(got))
	}
	h.remote = true
	if got := result(t, h.do(t, 0, proto.ReqIdentify, proto.U32s(0))); got != proto.ResultRemote {
		t.Fatalf("remote identify: %s", proto.ResultString(got))
	}
}

func TestEnrollListDelete(t *testing.T) {
	h := newHarness(&fakeReader{})
	enroll := func(peer, uid uint32, sub uint16) []proto.Frame {
		return h.do(t, peer, proto.ReqEnroll, proto.U16(proto.U32s(uid), sub))
	}
	fs := enroll(1000, 1000, 2)
	want := []uint16{proto.EvPrompt, proto.EvProgress, proto.EvRetry, proto.EvProgress, proto.EvResult}
	if result(t, fs) != proto.ResultMatch || !equal(types(fs), want) {
		t.Fatalf("enroll events %x", types(fs))
	}
	if got := result(t, enroll(1000, 1000, 2)); got != proto.ResultExists {
		t.Fatalf("again: %s", proto.ResultString(got))
	}
	if got := result(t, enroll(1000, 1001, 2)); got != proto.ResultDenied {
		t.Fatalf("for someone else: %s", proto.ResultString(got))
	}
	if got := result(t, enroll(0, 1001, 7)); got != proto.ResultMatch {
		t.Fatalf("root for someone else: %s", proto.ResultString(got))
	}
	if got := result(t, enroll(1000, 1000, 0)); got != proto.ResultBadRequest {
		t.Fatalf("subtype 0: %s", proto.ResultString(got))
	}

	list := func(peer, uid uint32) []proto.Frame { return h.do(t, peer, proto.ReqList, proto.U32s(uid)) }
	if fs := list(1000, 1000); result(t, fs) != proto.ResultMatch || len(fs) != 2 {
		t.Fatalf("own list %x", types(fs))
	}
	if fs := list(0, proto.AllUsers); len(fs) != 3 {
		t.Fatalf("everyone %x", types(fs))
	}
	if got := result(t, list(1000, proto.AllUsers)); got != proto.ResultDenied {
		t.Fatalf("non-root everyone: %s", proto.ResultString(got))
	}

	del := func(peer, uid uint32) uint32 {
		return result(t, h.do(t, peer, proto.ReqDelete, proto.U16(proto.U32s(uid), 0)))
	}
	if got := del(1000, 1001); got != proto.ResultDenied {
		t.Fatalf("delete someone else's: %s", proto.ResultString(got))
	}
	if got := del(1000, 1000); got != proto.ResultMatch {
		t.Fatalf("delete own: %s", proto.ResultString(got))
	}
	if got := del(1000, 1000); got != proto.ResultNotEnrolled {
		t.Fatalf("delete again: %s", proto.ResultString(got))
	}
}

func TestBadRequests(t *testing.T) {
	h := newHarness(&fakeReader{})
	for _, req := range []struct {
		typ     uint16
		payload []byte
	}{
		{proto.ReqVerify, proto.U32s(1)},
		{proto.ReqIdentify, nil},
		{proto.ReqEnroll, proto.U32s(1)},
		{proto.ReqList, nil},
		{proto.ReqDelete, proto.U32s(1)},
		{0x7f, nil},
	} {
		if got := result(t, h.do(t, 0, req.typ, req.payload)); got != proto.ResultBadRequest {
			t.Errorf("request %x: %s", req.typ, proto.ResultString(got))
		}
	}
}

func TestGarbageRequest(t *testing.T) {
	h := newHarness(&fakeReader{})
	client, server := net.Pipe()
	h.s.peer = func(net.Conn) (Peer, error) { return Peer{}, nil }
	go func() { h.s.handle(context.Background(), server); server.Close() }()
	client.Write([]byte{1, 0, 0xff, 0xff})
	f, err := proto.Read(client)
	if err != nil || f.Type != proto.EvResult {
		t.Fatalf("%+v, %v", f, err)
	}
	if v, _ := f.Fields(4); v[0] != proto.ResultBadRequest {
		t.Fatalf("result %d", v[0])
	}
}

func TestServeOverUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fpd.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{enrolled: map[uint32][]uint16{uint32(os.Getuid()): {2}}, outcomes: []outcome{{match: true}}}
	s := New(r, slog.New(slog.DiscardHandler), nil)
	done := make(chan error)
	go func() { done <- s.Serve(context.Background(), ln) }()

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Real SO_PEERCRED: this process's uid may verify itself.
	proto.Write(c, proto.ReqVerify, verifyReq(uint32(os.Getuid()), 0, 1))
	var last proto.Frame
	for last.Type != proto.EvResult {
		if last, err = proto.Read(c); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := last.Fields(4); v[0] != proto.ResultMatch {
		t.Fatalf("result %s", proto.ResultString(v[0]))
	}
	if _, err := proto.Read(c); !errors.Is(err, io.EOF) {
		t.Fatalf("connection left open: %v", err)
	}
	c.Close()
	ln.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := peerCred(&net.TCPConn{}); err == nil {
		t.Fatal("credentials from a non-unix connection")
	}
}

func TestRemoteSession(t *testing.T) {
	proc, run := t.TempDir(), t.TempDir()
	write := func(path, s string) {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(s), 0o644)
	}
	write(filepath.Join(proc, "10", "cgroup"), "0::/user.slice/user-1000.slice/session-7.scope\n")
	write(filepath.Join(run, "systemd", "sessions", "7"), "UID=1000\nREMOTE=1\nTYPE=tty\n")
	write(filepath.Join(proc, "11", "cgroup"), "0::/user.slice/user-1000.slice/session-2.scope\n")
	write(filepath.Join(run, "systemd", "sessions", "2"), "UID=1000\nREMOTE=0\n")
	write(filepath.Join(proc, "12", "cgroup"), "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kitty-1.scope\n")
	write(filepath.Join(proc, "13", "cgroup"), "0::/user.slice/user-1000.slice/session-9.scope\n") // no session file
	write(filepath.Join(proc, "14", "cgroup"), "garbage\n12:pids:/user.slice/session-7.scope\n")
	write(filepath.Join(proc, "15", "cgroup"), "0::/user.slice/user-1000.slice/session-3.scope\n")
	write(filepath.Join(run, "systemd", "sessions", "3"), "UID=1000\n")
	remote := RemoteSession(proc, run)
	for pid, want := range map[int32]bool{10: true, 11: false, 12: false, 13: false, 14: true, 15: false, 99: false} {
		if got := remote(pid); got != want {
			t.Errorf("pid %d: remote %v, want %v", pid, got, want)
		}
	}
}

func TestPeerString(t *testing.T) {
	if (Peer{UID: 1, PID: 2}).String() != "uid 1 pid 2" {
		t.Fatal()
	}
}
