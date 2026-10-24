package fprint

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"git.airies.net/vifair22/tp-fingerprint/internal/server"
)

// privateBus starts a dbus-daemon of our own and returns its address.
func privateBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "bus.conf")
	os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>custom</type>
  <listen>unix:path=`+filepath.Join(dir, "bus")+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>`), 0o600)
	cmd := exec.Command(daemon, "--config-file", conf, "--nofork", "--nopidfile", "--print-address")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(addr)
}

func connect(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	c, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// fakeReader holds enrolled fingers; Enroll plays touches from a script,
// or waits for cancellation when block is set.
type fakeReader struct {
	mu        sync.Mutex
	enrolled  map[uint32][]uint16
	touches   []error // nil: accepted
	enrollErr error
	deleteErr error
	block     bool
}

// set changes the fake under its lock, since the service reads it from its
// own goroutines.
func (f *fakeReader) set(fn func(*fakeReader)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeReader) Verify(context.Context, uint32, func(), func()) (bool, error) {
	return false, errors.New("not used")
}
func (f *fakeReader) Identify(context.Context, func(), func()) (server.Enrolled, bool, error) {
	return server.Enrolled{}, false, errors.New("not used")
}

func (f *fakeReader) Enroll(ctx context.Context, uid uint32, sub uint16, prompt func(), progress func(int, error)) error {
	prompt()
	f.mu.Lock()
	block, touches, enrollErr := f.block, f.touches, f.enrollErr
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	n := 0
	for _, e := range touches {
		if e == nil {
			n++
		}
		progress(n, e)
	}
	if enrollErr != nil {
		return enrollErr
	}
	f.mu.Lock()
	f.enrolled[uid] = append(f.enrolled[uid], sub)
	f.mu.Unlock()
	return nil
}

func (f *fakeReader) List(uid uint32) ([]server.Enrolled, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []server.Enrolled
	for _, s := range f.enrolled[uid] {
		out = append(out, server.Enrolled{UID: uid, Subtype: s})
	}
	return out, nil
}

func (f *fakeReader) Delete(uid uint32, sub uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if len(f.enrolled[uid]) == 0 {
		return server.ErrNotEnrolled
	}
	if sub == 0 {
		delete(f.enrolled, uid)
		return nil
	}
	kept := f.enrolled[uid][:0]
	found := false
	for _, s := range f.enrolled[uid] {
		if s == sub {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	f.enrolled[uid] = kept
	if !found {
		return server.ErrNotEnrolled
	}
	return nil
}

// gate is a one-at-a-time sensor lock, as server.Server's.
type gate struct{ mu sync.Mutex }

func (g *gate) Acquire() (func(), bool) {
	if !g.mu.TryLock() {
		return nil, false
	}
	return g.mu.Unlock, true
}

type rig struct {
	addr   string
	svc    *Service
	reader *fakeReader
	gate   *gate
	me     uint32
}

func newRig(t *testing.T) *rig {
	t.Helper()
	addr := privateBus(t)
	r := &rig{addr: addr, reader: &fakeReader{enrolled: map[uint32][]uint16{}}, gate: &gate{}, me: uint32(os.Getuid())}
	users := map[string]uint32{"me": r.me, "other": r.me + 1}
	r.svc = New(connect(t, addr), r.reader, r.gate, slog.New(slog.DiscardHandler), func(n string) (uint32, error) {
		if uid, ok := users[n]; ok {
			return uid, nil
		}
		return 0, errors.New("unknown user")
	})
	if err := r.svc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.svc.Close)
	return r
}

func (r *rig) device(t *testing.T, c *dbus.Conn) dbus.BusObject { return c.Object(BusName, DevicePath) }

func errName(err error) string {
	var de dbus.Error
	if errors.As(err, &de) {
		return de.Name
	}
	return ""
}

func getProp(t *testing.T, dev dbus.BusObject, name string) any {
	t.Helper()
	v, err := dev.GetProperty(deviceIface + "." + name)
	if err != nil {
		t.Fatalf("property %s: %v", name, err)
	}
	return v.Value()
}

func TestManagerAndIntrospection(t *testing.T) {
	r := newRig(t)
	c := connect(t, r.addr)
	var def dbus.ObjectPath
	if err := c.Object(BusName, ManagerPath).Call(managerIface+".GetDefaultDevice", 0).Store(&def); err != nil || def != DevicePath {
		t.Fatalf("default device %v, %v", def, err)
	}
	var all []dbus.ObjectPath
	if err := c.Object(BusName, ManagerPath).Call(managerIface+".GetDevices", 0).Store(&all); err != nil || len(all) != 1 {
		t.Fatalf("devices %v, %v", all, err)
	}
	var xml string
	if err := c.Object(BusName, DevicePath).Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"EnrollStart", "EnrollStatus", "num-enroll-stages", "DeleteEnrolledFinger", "org.freedesktop.DBus.Properties"} {
		if !strings.Contains(xml, want) {
			t.Errorf("introspection lacks %s", want)
		}
	}
	if err := c.Object(BusName, ManagerPath).Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil || !strings.Contains(xml, "GetDefaultDevice") {
		t.Fatalf("manager introspection: %v", err)
	}
	dev := r.device(t, c)
	if getProp(t, dev, "scan-type") != "press" || getProp(t, dev, "num-enroll-stages") != int32(-1) {
		t.Fatal("unclaimed properties")
	}
}

func TestListAndAuthorization(t *testing.T) {
	r := newRig(t)
	dev := r.device(t, connect(t, r.addr))
	var names []string
	if err := dev.Call(deviceIface+".ListEnrolledFingers", 0, "").Store(&names); errName(err) != errPrefix+"NoEnrolledPrints" {
		t.Fatalf("empty list: %v", err)
	}
	r.reader.set(func(f *fakeReader) { f.enrolled[r.me] = []uint16{2, 7} })
	if err := dev.Call(deviceIface+".ListEnrolledFingers", 0, "me").Store(&names); err != nil ||
		strings.Join(names, ",") != "right-index-finger,left-index-finger" {
		t.Fatalf("list %v, %v", names, err)
	}
	if r.me != 0 {
		err := dev.Call(deviceIface+".ListEnrolledFingers", 0, "other").Store(&names)
		if errName(err) != errPrefix+"PermissionDenied" {
			t.Fatalf("someone else's: %v", err)
		}
		if err := dev.Call(deviceIface+".Claim", 0, "other").Err; errName(err) != errPrefix+"PermissionDenied" {
			t.Fatalf("claim for someone else: %v", err)
		}
		if err := dev.Call(deviceIface+".DeleteEnrolledFingers", 0, "other").Err; errName(err) != errPrefix+"PermissionDenied" {
			t.Fatalf("delete someone else's: %v", err)
		}
	}
	if err := dev.Call(deviceIface+".ListEnrolledFingers", 0, "nobody-at-all").Store(&names); err == nil {
		t.Fatal("listed for an unknown user")
	}
	// The sensor busy elsewhere (the lock screen, sudo).
	release, _ := r.gate.Acquire()
	if err := dev.Call(deviceIface+".ListEnrolledFingers", 0, "").Store(&names); errName(err) != errPrefix+"AlreadyInUse" {
		t.Fatalf("list while busy: %v", err)
	}
	release()
}

func TestClaimRelease(t *testing.T) {
	r := newRig(t)
	a, b := connect(t, r.addr), connect(t, r.addr)
	devA, devB := r.device(t, a), r.device(t, b)
	if err := devA.Call(deviceIface+".Release", 0).Err; errName(err) != errPrefix+"ClaimDevice" {
		t.Fatalf("release unclaimed: %v", err)
	}
	if err := devA.Call(deviceIface+".Claim", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	if getProp(t, devA, "num-enroll-stages") != int32(EnrollStages) {
		t.Fatal("num-enroll-stages while claimed")
	}
	if err := devB.Call(deviceIface+".Claim", 0, "").Err; errName(err) != errPrefix+"AlreadyInUse" {
		t.Fatalf("second claim: %v", err)
	}
	if err := devB.Call(deviceIface+".Release", 0).Err; errName(err) != errPrefix+"ClaimDevice" {
		t.Fatalf("release by a non-claimant: %v", err)
	}
	if err := devA.Call(deviceIface+".Release", 0).Err; err != nil {
		t.Fatal(err)
	}
	if getProp(t, devA, "num-enroll-stages") != int32(-1) {
		t.Fatal("num-enroll-stages after release")
	}
	// A claimant that leaves the bus loses its claim.
	if err := devB.Call(deviceIface+".Claim", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	b.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := devA.Call(deviceIface+".Claim", 0, "").Err
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("claim not released after the claimant left: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// statuses collects EnrollStatus signals until a done one.
func statuses(t *testing.T, c *dbus.Conn) func() []string {
	t.Helper()
	if err := c.AddMatchSignal(dbus.WithMatchObjectPath(DevicePath), dbus.WithMatchInterface(deviceIface),
		dbus.WithMatchMember("EnrollStatus")); err != nil {
		t.Fatal(err)
	}
	ch := make(chan *dbus.Signal, 64)
	c.Signal(ch)
	return func() []string {
		var got []string
		for {
			select {
			case sig := <-ch:
				got = append(got, sig.Body[0].(string))
				if sig.Body[1].(bool) {
					return got
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no final EnrollStatus; got %v", got)
			}
		}
	}
}

func TestEnroll(t *testing.T) {
	r := newRig(t)
	c := connect(t, r.addr)
	dev := r.device(t, c)
	wait := statuses(t, c)
	if err := dev.Call(deviceIface+".EnrollStart", 0, "right-index-finger").Err; errName(err) != errPrefix+"ClaimDevice" {
		t.Fatalf("enroll unclaimed: %v", err)
	}
	if err := dev.Call(deviceIface+".Claim", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".EnrollStart", 0, "nose").Err; errName(err) != errPrefix+"InvalidFingername" {
		t.Fatalf("bad finger: %v", err)
	}
	// Fourteen accepted touches and one rejected: stage signals stop one
	// short of EnrollStages, then completion.
	r.reader.set(func(f *fakeReader) {
		f.touches = make([]error, 15)
		f.touches[3] = errors.New("smudge")
	})
	if err := dev.Call(deviceIface+".EnrollStart", 0, "right-index-finger").Err; err != nil {
		t.Fatal(err)
	}
	got := wait()
	passed := 0
	for _, s := range got {
		if s == "enroll-stage-passed" {
			passed++
		}
	}
	if passed != EnrollStages-1 || got[len(got)-1] != "enroll-completed" || !contains(got, "enroll-retry-scan") {
		t.Fatalf("statuses %v (%d stage-passed)", got, passed)
	}
	if getProp(t, dev, "finger-needed") != false {
		t.Fatal("finger-needed after enrollment")
	}
	if fs, _ := r.reader.List(r.me); len(fs) != 1 || fs[0].Subtype != 2 {
		t.Fatalf("enrolled %v", fs)
	}

	// Enrolling the same finger again replaces it.
	r.reader.set(func(f *fakeReader) { f.touches = []error{nil} })
	if err := dev.Call(deviceIface+".EnrollStart", 0, "right-index-finger").Err; err != nil {
		t.Fatal(err)
	}
	if got := wait(); got[len(got)-1] != "enroll-completed" {
		t.Fatalf("re-enroll %v", got)
	}
	if fs, _ := r.reader.List(r.me); len(fs) != 1 {
		t.Fatalf("re-enrolled finger duplicated: %v", fs)
	}

	// Failures end with the fprintd status for them.
	for _, tt := range []struct {
		err  error
		want string
	}{{server.ErrUnavailable, "enroll-disconnected"}, {errors.New("sensor said no"), "enroll-failed"}} {
		r.reader.set(func(f *fakeReader) { f.enrollErr = tt.err })
		if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; err != nil {
			t.Fatal(err)
		}
		if got := wait(); got[len(got)-1] != tt.want {
			t.Fatalf("%v: %v", tt.err, got)
		}
	}
	r.reader.set(func(f *fakeReader) {
		f.enrollErr = nil
		f.deleteErr = errors.New("db broken")
	})
	if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; err != nil {
		t.Fatal(err)
	}
	if got := wait(); got[len(got)-1] != "enroll-failed" {
		t.Fatalf("delete failure: %v", got)
	}
	r.reader.set(func(f *fakeReader) { f.deleteErr = nil })

	// The sensor busy elsewhere.
	release, _ := r.gate.Acquire()
	if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; errName(err) != errPrefix+"AlreadyInUse" {
		t.Fatalf("enroll while busy: %v", err)
	}
	release()
}

func TestEnrollStop(t *testing.T) {
	r := newRig(t)
	dev := r.device(t, connect(t, r.addr))
	if err := dev.Call(deviceIface+".Claim", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".EnrollStop", 0).Err; errName(err) != errPrefix+"NoActionInProgress" {
		t.Fatalf("stop with nothing running: %v", err)
	}
	r.reader.set(func(f *fakeReader) { f.block = true })
	if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; errName(err) != errPrefix+"AlreadyInUse" {
		t.Fatalf("second enroll: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for getProp(t, dev, "finger-needed") != true {
		if time.Now().After(deadline) {
			t.Fatal("finger-needed never set")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := dev.Call(deviceIface+".EnrollStop", 0).Err; err != nil {
		t.Fatal(err)
	}
	rel, ok := r.gate.Acquire()
	if !ok {
		t.Fatal("sensor still held after EnrollStop")
	}
	rel()
	// Release also stops a running enrollment.
	if err := dev.Call(deviceIface+".EnrollStart", 0, "left-thumb").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".Release", 0).Err; err != nil {
		t.Fatal(err)
	}
	if _, ok := r.gate.Acquire(); !ok {
		t.Fatal("sensor still held after Release")
	}
}

func TestDelete(t *testing.T) {
	r := newRig(t)
	dev := r.device(t, connect(t, r.addr))
	r.reader.set(func(f *fakeReader) { f.enrolled[r.me] = []uint16{2, 7} })
	if err := dev.Call(deviceIface+".DeleteEnrolledFinger", 0, "left-index-finger").Err; errName(err) != errPrefix+"ClaimDevice" {
		t.Fatalf("delete unclaimed: %v", err)
	}
	if err := dev.Call(deviceIface+".Claim", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".DeleteEnrolledFinger", 0, "nose").Err; errName(err) != errPrefix+"InvalidFingername" {
		t.Fatalf("bad finger: %v", err)
	}
	if err := dev.Call(deviceIface+".DeleteEnrolledFinger", 0, "left-index-finger").Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".DeleteEnrolledFinger", 0, "left-index-finger").Err; errName(err) != errPrefix+"NoEnrolledPrints" {
		t.Fatalf("delete twice: %v", err)
	}
	if err := dev.Call(deviceIface+".DeleteEnrolledFingers2", 0).Err; err != nil {
		t.Fatal(err)
	}
	if fs, _ := r.reader.List(r.me); len(fs) != 0 {
		t.Fatalf("left %v", fs)
	}
	if err := dev.Call(deviceIface+".Release", 0).Err; err != nil {
		t.Fatal(err)
	}
	if err := dev.Call(deviceIface+".DeleteEnrolledFingers2", 0).Err; errName(err) != errPrefix+"ClaimDevice" {
		t.Fatalf("delete-all unclaimed: %v", err)
	}
	r.reader.set(func(f *fakeReader) { f.enrolled[r.me] = []uint16{3} })
	if err := dev.Call(deviceIface+".DeleteEnrolledFingers", 0, "").Err; err != nil {
		t.Fatal(err)
	}
	r.reader.set(func(f *fakeReader) { f.deleteErr = server.ErrUnavailable })
	if err := dev.Call(deviceIface+".DeleteEnrolledFingers", 0, "").Err; errName(err) != errPrefix+"Internal" {
		t.Fatalf("unavailable: %v", err)
	}
	r.reader.set(func(f *fakeReader) { f.deleteErr = errors.New("db broken") })
	if err := dev.Call(deviceIface+".DeleteEnrolledFingers", 0, "").Err; errName(err) != errPrefix+"Internal" {
		t.Fatalf("broken: %v", err)
	}
}

func TestNameTaken(t *testing.T) {
	addr := privateBus(t)
	first := New(connect(t, addr), &fakeReader{}, &gate{}, slog.New(slog.DiscardHandler), nil)
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	second := New(connect(t, addr), &fakeReader{}, &gate{}, slog.New(slog.DiscardHandler), nil)
	if err := second.Start(); err == nil || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("second owner: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
