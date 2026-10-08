package device

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
	"git.airies.net/vifair22/t480-fingerprint/internal/trust"
	"git.airies.net/vifair22/t480-fingerprint/internal/usbfs"
	"git.airies.net/vifair22/t480-fingerprint/internal/validity"
)

// fakeSensor is an opened sensor with a database of users and a scripted
// next scan.
type fakeSensor struct {
	noStorage bool
	users     map[uint16]*validity.User // by record id
	nextID    uint16
	scan      func() (*validity.Match, error)
	failDB    error
	closed    bool
	shutdown  bool
	// awake tracks Wake/Idle; wakeErr makes the next Wake fail.
	awake   bool
	idles   int
	wakeErr error
	// key is the sensor's identity for pinning.
	key string
}

func newFake() *fakeSensor {
	return &fakeSensor{users: map[uint16]*validity.User{}, nextID: 10, key: "sensor A"}
}

// tidOf is the template id the fake gives finger record id.
func tidOf(id uint16) []byte { return []byte(fmt.Sprintf("tid-%d", id)) }

// fingerRecord lays out a finger record's value as the sensor stores it
// (validity's fingerData), holding tid.
func fingerRecord(subtype uint16, tid []byte) []byte {
	le := binary.LittleEndian
	tmpl := []byte("template")
	inner := le.AppendUint16(nil, 1)
	inner = le.AppendUint16(inner, uint16(len(tmpl)))
	inner = append(inner, tmpl...)
	inner = le.AppendUint16(inner, 2)
	inner = le.AppendUint16(inner, uint16(len(tid)))
	inner = append(inner, tid...)
	v := le.AppendUint16(nil, subtype)
	v = le.AppendUint16(v, 3)
	v = le.AppendUint16(v, uint16(len(inner)))
	v = le.AppendUint16(v, 0x20)
	return append(append(v, inner...), make([]byte, 0x20)...)
}

func (f *fakeSensor) RecordValue(id uint16) (*validity.Record, error) {
	for _, u := range f.users {
		for _, fg := range u.Fingers {
			if fg.ID == id {
				return &validity.Record{ID: id, Value: fingerRecord(fg.Subtype, tidOf(id))}, nil
			}
		}
	}
	return nil, errors.New("no such record")
}

func (f *fakeSensor) SensorKey() []byte { return []byte(f.key) }

func (f *fakeSensor) add(uid uint32, subtypes ...uint16) *validity.User {
	u := &validity.User{ID: f.nextID, SID: validity.UIDSID(uid)}
	f.nextID++
	for _, s := range subtypes {
		u.Fingers = append(u.Fingers, validity.Finger{ID: f.nextID, Subtype: s})
		f.nextID++
	}
	f.users[u.ID] = u
	return u
}

func (f *fakeSensor) Storage() (*validity.Storage, error) {
	if f.failDB != nil {
		return nil, f.failDB
	}
	if f.noStorage {
		return nil, validity.ErrNoStorage
	}
	s := &validity.Storage{ID: 3, Name: validity.StorageName}
	for id := range f.users {
		s.Users = append(s.Users, validity.RecordRef{ID: id})
	}
	return s, nil
}

func (f *fakeSensor) LookupUser(_ uint16, sid validity.SID) (*validity.User, error) {
	for _, u := range f.users {
		if u.SID.String() == sid.String() {
			return u, nil
		}
	}
	return nil, nil
}

func (f *fakeSensor) User(id uint16) (*validity.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, errors.New("no such record")
}

func (f *fakeSensor) Users(s *validity.Storage) ([]*validity.User, error) {
	var out []*validity.User
	for _, r := range s.Users {
		out = append(out, f.users[r.ID])
	}
	return out, nil
}

func (f *fakeSensor) DeleteRecord(id uint16) error {
	if _, ok := f.users[id]; ok {
		delete(f.users, id)
		return nil
	}
	for _, u := range f.users {
		for i, fg := range u.Fingers {
			if fg.ID == id {
				u.Fingers = append(u.Fingers[:i], u.Fingers[i+1:]...)
				return nil
			}
		}
	}
	return errors.New("no such record")
}

// Identify runs the scripted scan; a match that names no template gets the
// matched finger's, as the sensor reports it.
func (f *fakeSensor) Identify(ctx context.Context, retry func(error)) (*validity.Match, error) {
	retry(validity.ErrScan)
	m, err := f.scan()
	if m != nil && m.Hash == nil {
		if u, ok := f.users[m.User]; ok {
			for _, fg := range u.Fingers {
				if fg.Subtype == m.Subtype || m.Subtype == 0 {
					m.Hash, m.Subtype = tidOf(fg.ID), fg.Subtype
					break
				}
			}
		}
	}
	return m, err
}

func (f *fakeSensor) Enroll(_ context.Context, sid validity.SID, subtype uint16, progress func(validity.EnrollEvent)) (uint16, []byte, error) {
	progress(validity.EnrollEvent{Touch: 1})
	uid, _ := sid.UID()
	u, _ := f.LookupUser(0, sid)
	if u == nil {
		u = f.add(uid)
	}
	id := f.nextID
	u.Fingers = append(u.Fingers, validity.Finger{ID: id, Subtype: subtype})
	f.nextID++
	return id, tidOf(id), nil
}

func (f *fakeSensor) Wake() error {
	if f.wakeErr != nil {
		err := f.wakeErr
		f.wakeErr = nil
		return err
	}
	f.awake = true
	return nil
}

func (f *fakeSensor) Idle() error {
	f.awake = false
	f.idles++
	return nil
}

func (f *fakeSensor) Shutdown() error { f.shutdown = true; return nil }
func (f *fakeSensor) Close() error    { f.closed = true; return nil }

// rig is a Device over fake bus positions and fake opens.
type rig struct {
	d       *Device
	at      usbfs.Info
	gone    bool
	opens   int
	sensor  *fakeSensor
	openErr error
	// The kernel's suspended-time count, as the device reads it; guarded
	// by r.d.mu once requests run.
	sleptMs  int64
	sleptErr error
}

func newRig(t *testing.T) *rig {
	r := &rig{at: usbfs.Info{Bus: 1, Addr: 5}, sensor: newFake()}
	dir := t.TempDir()
	r.d = &Device{cfg: Config{Log: slog.New(slog.DiscardHandler),
		PinPath: filepath.Join(dir, "sensor-pin"), LedgerPath: filepath.Join(dir, "enrolled")},
		pollEvery: time.Millisecond,
		idleGrace: time.Hour, suspendedMs: func(usbfs.Info) (int64, error) { return r.sleptMs, r.sleptErr }}
	r.d.locate = func() (usbfs.Info, error) {
		if r.gone {
			return usbfs.Info{}, usbfs.ErrNotFound
		}
		return r.at, nil
	}
	r.d.open = func(usbfs.Info) (sensor, error) {
		if r.openErr != nil {
			return nil, r.openErr
		}
		r.opens++
		// Opening a usbfs device wakes it.
		r.sensor.awake = true
		return r.sensor, nil
	}
	return r
}

func nop()              {}
func nopErr(int, error) {}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	me := r.sensor.add(1000, 2)
	other := r.sensor.add(1001, 7)

	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID, Subtype: 2}, nil }
	retries := 0
	ok, err := r.d.Verify(ctx, 1000, nop, func() { retries++ })
	if err != nil || !ok || retries != 1 {
		t.Fatalf("own finger: %v, %v, %d retries", ok, err, retries)
	}
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: other.ID}, nil }
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || ok {
		t.Fatalf("someone else's finger: %v, %v", ok, err)
	}
	r.sensor.scan = func() (*validity.Match, error) { return nil, validity.ErrNoMatch }
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || ok {
		t.Fatalf("unknown finger: %v, %v", ok, err)
	}
	if _, err := r.d.Verify(ctx, 1002, nop, nop); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("no user record: %v", err)
	}
	r.sensor.add(1003)
	if _, err := r.d.Verify(ctx, 1003, nop, nop); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("user with no fingers: %v", err)
	}
	r.sensor.noStorage = true
	if _, err := r.d.Verify(ctx, 1000, nop, nop); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("no storage: %v", err)
	}
	if r.opens != 1 {
		t.Fatalf("opened %d times for one sensor", r.opens)
	}
}

func TestReopenAndDrop(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	me := r.sensor.add(1000, 2)
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }
	r.d.Verify(ctx, 1000, nop, nop)

	if err := r.d.Warm(); err != nil || r.opens != 1 {
		t.Fatalf("warm an open sensor: %v, %d opens", err, r.opens)
	}

	// After a resume the sensor comes back at another address.
	r.at.Addr = 6
	first := r.sensor
	r.sensor = newFake()
	r.sensor.users = first.users
	r.sensor.scan = first.scan
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok {
		t.Fatalf("after re-enumeration: %v, %v", ok, err)
	}
	if r.opens != 2 || !first.closed {
		t.Fatalf("opens %d, old handle closed %v", r.opens, first.closed)
	}

	// A sensor that fails mid-request is reopened and the scan rerun,
	// within the same request.
	fails := 1
	r.sensor.scan = func() (*validity.Match, error) {
		if fails > 0 {
			fails--
			return nil, usbfs.ErrDisconnected
		}
		return &validity.Match{User: me.ID}, nil
	}
	prompts := 0
	if ok, err := r.d.Verify(ctx, 1000, func() { prompts++ }, nop); err != nil || !ok || prompts != 2 || r.opens != 3 {
		t.Fatalf("transient failure: %v, %v, %d prompts, %d opens", ok, err, prompts, r.opens)
	}
	// One that keeps failing is given up on after maxReopens reopens.
	bctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r.sensor.scan = func() (*validity.Match, error) { return nil, usbfs.ErrDisconnected }
	before := r.opens
	if _, err := r.d.Verify(bctx, 1000, nop, nop); !errors.Is(err, usbfs.ErrDisconnected) {
		t.Fatalf("persistent failure: %v", err)
	}
	// The first attempt reuses the open session; each retry reopens.
	if r.opens-before != maxReopens {
		t.Fatalf("%d opens for a persistent failure, want %d", r.opens-before, maxReopens)
	}
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }
	if ok, _ := r.d.Verify(ctx, 1000, nop, nop); !ok {
		t.Fatal("no match after the failures")
	}
	opensSoFar := r.opens

	// Rejected scans and cancellation keep the session.
	for _, keep := range []error{validity.ErrScan, validity.ErrEnrollAborted} {
		r.sensor.scan = func() (*validity.Match, error) { return nil, keep }
		r.d.Verify(ctx, 1000, nop, nop)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	r.sensor.scan = func() (*validity.Match, error) { return nil, c.Err() }
	r.d.Verify(c, 1000, nop, nop)
	if r.opens != opensSoFar {
		t.Fatalf("session dropped for a benign outcome (%d opens, was %d)", r.opens, opensSoFar)
	}

	// With a deadline (sudo), a sensor that is not on the bus, or will not
	// open, is unavailable at once.
	r.gone = true
	start := time.Now()
	if _, err := r.d.Verify(bctx, 1000, nop, nop); !errors.Is(err, server.ErrUnavailable) || time.Since(start) > time.Second {
		t.Fatalf("missing sensor: %v after %v", err, time.Since(start))
	}
	r.gone = false
	r.openErr = errors.New("handshake failed")
	if _, err := r.d.Verify(bctx, 1000, nop, nop); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("unopenable sensor: %v", err)
	}
	r.openErr = nil
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok {
		t.Fatalf("once it opens again: %v, %v", ok, err)
	}

	if err := r.d.Close(); err != nil || !r.sensor.shutdown {
		t.Fatalf("close: %v, rebooted %v", err, r.sensor.shutdown)
	}
	if err := r.d.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestIdentify(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	me := r.sensor.add(1000, 2)
	foreign := r.sensor.add(0)
	foreign.SID = validity.SID{Revision: 1, Auth: 5, SubAuth: []uint32{18}}

	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID, Subtype: 2}, nil }
	e, ok, err := r.d.Identify(ctx, nop, nop)
	if err != nil || !ok || e.UID != 1000 || e.Subtype != 2 {
		t.Fatalf("%+v, %v, %v", e, ok, err)
	}
	for name, scan := range map[string]func() (*validity.Match, error){
		"no match":     func() (*validity.Match, error) { return nil, validity.ErrNoMatch },
		"foreign user": func() (*validity.Match, error) { return &validity.Match{User: foreign.ID}, nil },
	} {
		r.sensor.scan = scan
		if _, ok, err := r.d.Identify(ctx, nop, nop); ok || err != nil {
			t.Errorf("%s: %v, %v", name, ok, err)
		}
	}
	// A record fpd has no template for matches nobody: whose finger it is
	// comes from the ledger, not the sensor's say-so.
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: 999}, nil }
	if _, ok, err := r.d.Identify(ctx, nop, nop); ok || err != nil {
		t.Errorf("match on an unknown record: %v, %v", ok, err)
	}
	r.sensor.scan = func() (*validity.Match, error) { return nil, errors.New("usb") }
	if _, _, err := r.d.Identify(ctx, nop, nop); err == nil {
		t.Error("scan failure swallowed")
	}
	r.gone = true
	bctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, _, err := r.d.Identify(bctx, nop, nop); !errors.Is(err, server.ErrUnavailable) {
		t.Errorf("missing sensor: %v", err)
	}
}

// The lock screen asks with no deadline and never asks twice, so its
// request outlives a suspend: it waits for the sensor to come back.
func TestNoDeadlineWaitsForTheSensor(t *testing.T) {
	r := newRig(t)
	me := r.sensor.add(1000, 2)
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }

	// Asked while the sensor is still re-enumerating after a resume.
	r.gone = true
	var mu sync.Mutex
	go func() {
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		r.gone = false
		mu.Unlock()
	}()
	r.d.locate = func() (usbfs.Info, error) {
		mu.Lock()
		defer mu.Unlock()
		if r.gone {
			return usbfs.Info{}, usbfs.ErrNotFound
		}
		return r.at, nil
	}
	if ok, err := r.d.Verify(context.Background(), 1000, nop, nop); err != nil || !ok {
		t.Fatalf("after waiting: %v, %v", ok, err)
	}

	// The caller hanging up (unlocking with the password) ends the wait.
	mu.Lock()
	r.gone = true
	mu.Unlock()
	r.d.drop()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	nodeadline, stop := context.WithCancel(context.Background())
	go func() { <-ctx.Done(); stop() }()
	if _, err := r.d.Verify(nodeadline, 1000, nop, nop); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
}

func TestEnrollListDelete(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.sensor.add(1001, 7)
	if err := r.d.Enroll(ctx, 1000, 2, nop, nopErr); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Enroll(ctx, 1000, 3, nop, nopErr); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Enroll(ctx, 1000, 2, nop, nopErr); !errors.Is(err, server.ErrExists) {
		t.Fatalf("again: %v", err)
	}
	mine, err := r.d.List(1000)
	if err != nil || len(mine) != 2 {
		t.Fatalf("own list %v, %v", mine, err)
	}
	all, _ := r.d.List(proto.AllUsers)
	if len(all) != 3 {
		t.Fatalf("all %v", all)
	}

	if err := r.d.Delete(1000, 3); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Delete(1000, 3); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("deleted twice: %v", err)
	}
	if err := r.d.Delete(1000, 0); err != nil {
		t.Fatal(err)
	}
	if mine, _ := r.d.List(1000); len(mine) != 0 {
		t.Fatalf("after deleting the user: %v", mine)
	}
	if err := r.d.Delete(1000, 0); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("delete a missing user: %v", err)
	}

	r.sensor.noStorage = true
	if l, err := r.d.List(proto.AllUsers); err != nil || l != nil {
		t.Fatalf("empty database: %v, %v", l, err)
	}
	if err := r.d.Enroll(ctx, 1000, 2, nop, nopErr); err != nil {
		t.Fatalf("enroll into an empty database: %v", err)
	}
	r.sensor.noStorage = false
	r.sensor.failDB = errors.New("db broken")
	if _, err := r.d.List(1000); err == nil {
		t.Fatal("list over a broken database")
	}
	if err := r.d.Enroll(ctx, 1000, 4, nop, nopErr); err == nil {
		t.Fatal("enroll over a broken database")
	}
	if err := r.d.Delete(1000, 0); err == nil {
		t.Fatal("delete over a broken database")
	}
	r.gone = true
	if _, err := r.d.List(1000); !errors.Is(err, server.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := r.d.Enroll(ctx, 1000, 4, nop, nopErr); !errors.Is(err, server.ErrUnavailable) {
		t.Fatal(err)
	}
	if err := r.d.Delete(1000, 0); !errors.Is(err, server.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestNewAndOpenFailures(t *testing.T) {
	d := New(Config{SecretPath: "/nonexistent/secret", Bus: usbfs.Bus{SysRoot: t.TempDir()}, Log: slog.New(slog.DiscardHandler)})
	bctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := d.Verify(bctx, 1, nop, nop); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("no sensor: %v", err)
	}
	if _, err := d.openReal(usbfs.Info{}); err == nil {
		t.Fatal("opened without a host secret")
	}

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, make([]byte, 32), 0o600)
	d.cfg.SecretPath = secret
	d.cfg.CalibPath = dir // a directory: unreadable as calibration data
	if _, err := d.openReal(usbfs.Info{}); err == nil {
		t.Fatal("opened with unreadable calibration data")
	}
	d.cfg.CalibPath = filepath.Join(dir, "calib")
	d.cfg.Bus = usbfs.Bus{DevRoot: dir} // no device node there
	if _, err := d.openReal(usbfs.Info{Bus: 1, Addr: 4}); err == nil {
		t.Fatal("opened a missing device node")
	}
}

// locked runs fn with the device's lock held, for looking at state the
// idle timer also touches.
func (r *rig) locked(fn func()) {
	r.d.mu.Lock()
	defer r.d.mu.Unlock()
	fn()
}

// Between requests the sensor may autosuspend, once idleGrace has passed.
// It loses its TLS session when it does, so a request after a real sleep
// reopens; one after an allowed but untaken sleep, or within the grace,
// keeps the session.
func TestIdleBetweenRequests(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.d.idleGrace = 5 * time.Millisecond
	me := r.sensor.add(1000, 2)
	r.sensor.scan = func() (*validity.Match, error) {
		if !r.sensor.awake {
			t.Error("scanned on a sensor that was not woken")
		}
		return &validity.Match{User: me.ID}, nil
	}
	waitAllowed := func(want bool) {
		t.Helper()
		for i := 0; i < 200; i++ {
			var got bool
			r.locked(func() { got = r.d.allowed })
			if got == want {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("suspend allowed never became %v", want)
	}

	if err := r.d.Warm(); err != nil {
		t.Fatal(err)
	}
	waitAllowed(true)
	r.locked(func() {
		if r.sensor.idles != 1 || r.sensor.awake {
			t.Fatalf("after the grace: %d idles, awake %v", r.sensor.idles, r.sensor.awake)
		}
	})

	// Allowed to sleep but did not: the session is reused.
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok || r.opens != 1 {
		t.Fatalf("untaken sleep: %v, %v, %d opens", ok, err, r.opens)
	}
	waitAllowed(true)
	// It slept: the next request reopens before using the sensor.
	r.locked(func() { r.sleptMs += 2500 })
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok || r.opens != 2 {
		t.Fatalf("after a sleep: %v, %v, %d opens", ok, err, r.opens)
	}
	// Within the grace no suspend is allowed at all.
	r.d.idleGrace = time.Hour
	r.d.List(1000)
	r.d.List(1000)
	r.locked(func() {
		if r.d.allowed {
			t.Fatal("suspend allowed within the grace")
		}
	})

	// A sensor that will not wake is reopened.
	r.d.idleGrace = 5 * time.Millisecond
	r.d.List(1000)
	waitAllowed(true)
	r.locked(func() { r.sensor.wakeErr = errors.New("device not responding") })
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok || r.opens != 3 {
		t.Fatalf("after a failed wake: %v, %v, %d opens", ok, err, r.opens)
	}

	// No suspend count, no suspend: the session could not be judged.
	waitAllowed(true)
	r.d.List(1000) // takes the sensor back without a reopen
	r.locked(func() { r.sleptErr = errors.New("no sysfs") })
	time.Sleep(30 * time.Millisecond)
	r.locked(func() {
		if r.d.allowed {
			t.Fatal("suspend allowed without a way to tell it happened")
		}
		r.sleptErr = nil
	})

	// Closing after a sleep releases the handle without a reboot over a
	// session that is gone; closing an awake sensor reboots it.
	r.d.List(1000)
	waitAllowed(true)
	r.locked(func() { r.sleptMs += 1000 })
	if err := r.d.Close(); err != nil || r.sensor.shutdown || !r.sensor.closed {
		t.Fatalf("close after a sleep: %v, shutdown %v, closed %v", err, r.sensor.shutdown, r.sensor.closed)
	}
	r.d.idleGrace = time.Hour
	r.d.List(1000)
	if err := r.d.Close(); err != nil || !r.sensor.shutdown {
		t.Fatalf("close while awake: %v, shutdown %v", err, r.sensor.shutdown)
	}
	r.d.idle() // nothing open: nothing to schedule
}

func TestReadSuspendedMs(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "power"), 0o755)
	os.WriteFile(filepath.Join(dir, "power", "runtime_suspended_time"), []byte("1234\n"), 0o644)
	if ms, err := readSuspendedMs(usbfs.Info{SysPath: dir}); err != nil || ms != 1234 {
		t.Fatalf("%d, %v", ms, err)
	}
	if _, err := readSuspendedMs(usbfs.Info{SysPath: t.TempDir()}); err == nil {
		t.Fatal("read a missing count")
	}
}

// F1: a sensor other than the pinned one is refused at once, even by a
// request with no deadline, which would otherwise wait and reopen.
func TestPinnedSensor(t *testing.T) {
	r := newRig(t)
	me := r.sensor.add(1000, 2)
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }
	if ok, err := r.d.Verify(context.Background(), 1000, nop, nop); err != nil || !ok {
		t.Fatalf("first use: %v, %v", ok, err)
	}
	if b, err := os.ReadFile(r.d.cfg.PinPath); err != nil || len(b) == 0 {
		t.Fatalf("no pin written: %v", err)
	}

	// Swap the sensor: the next open sees another key.
	r.d.drop()
	r.sensor.key = "sensor B"
	opens := r.opens
	_, err := r.d.Verify(context.Background(), 1000, nop, nop)
	if !errors.Is(err, trust.ErrSensorMismatch) || !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("swapped sensor: %v", err)
	}
	if r.opens-opens != 1 || !r.sensor.closed {
		t.Fatalf("%d opens for a swapped sensor, closed %v", r.opens-opens, r.sensor.closed)
	}
}

// F2: the ledger is adopted on first use, and a match counts only for a
// template fpd recorded for that user.
func TestLedger(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	me := r.sensor.add(1000, 2, 7)
	other := r.sensor.add(1001, 3)
	foreign := r.sensor.add(0, 5)
	foreign.SID = validity.SID{Revision: 1, Auth: 5, SubAuth: []uint32{18}}
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID, Subtype: 2}, nil }
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || !ok {
		t.Fatalf("adopted finger: %v, %v", ok, err)
	}
	l, exists, err := trust.LoadLedger(r.d.cfg.LedgerPath)
	if err != nil || !exists || len(l.Entries()) != 3 {
		t.Fatalf("adopted ledger: %+v, %v, %v", l.Entries(), exists, err)
	}

	// The sensor says "your record", but the template is not one fpd
	// enrolled for this user.
	r.sensor.scan = func() (*validity.Match, error) {
		return &validity.Match{User: me.ID, Subtype: 2, Hash: []byte("rogue template")}, nil
	}
	if ok, err := r.d.Verify(ctx, 1000, nop, nop); err != nil || ok {
		t.Fatalf("unknown template: %v, %v", ok, err)
	}
	// Nor is another user's template, even claimed under this record.
	r.sensor.scan = func() (*validity.Match, error) {
		return &validity.Match{User: me.ID, Hash: tidOf(other.Fingers[0].ID)}, nil
	}
	if ok, _ := r.d.Verify(ctx, 1000, nop, nop); ok {
		t.Fatal("matched on another user's template")
	}

	// A user the sensor holds but the ledger does not is not enrolled.
	r.sensor.add(1002, 4)
	if _, err := r.d.Verify(ctx, 1002, nop, nop); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("user missing from the ledger: %v", err)
	}
	// Identify names the ledger's owner.
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: other.ID}, nil }
	if e, ok, err := r.d.Identify(ctx, nop, nop); err != nil || !ok || e.UID != 1001 || e.Subtype != 3 {
		t.Fatalf("identify: %+v, %v, %v", e, ok, err)
	}
	// List shows only what the ledger backs: not 1002's finger, nor the
	// foreign one.
	if all, _ := r.d.List(proto.AllUsers); len(all) != 3 {
		t.Fatalf("list: %+v", all)
	}

	// Enroll records the new template; delete forgets it.
	if err := r.d.Enroll(ctx, 1000, 9, nop, nopErr); err != nil {
		t.Fatal(err)
	}
	l, _, _ = trust.LoadLedger(r.d.cfg.LedgerPath)
	if len(l.Entries()) != 4 {
		t.Fatalf("after enroll: %+v", l.Entries())
	}
	if err := r.d.Delete(1000, 9); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Delete(1001, 0); err != nil {
		t.Fatal(err)
	}
	l, _, _ = trust.LoadLedger(r.d.cfg.LedgerPath)
	if got := l.Entries(); len(got) != 2 || got[0].UID != 1000 || got[1].UID != 1000 {
		t.Fatalf("after deletes: %+v", got)
	}

	// An existing ledger is never re-adopted, even if empty.
	r2 := newRig(t)
	r2.d.cfg.LedgerPath = filepath.Join(t.TempDir(), "enrolled")
	empty, _, _ := trust.LoadLedger(r2.d.cfg.LedgerPath)
	empty.Replace(nil)
	mine := r2.sensor.add(1000, 2)
	r2.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: mine.ID}, nil }
	if _, err := r2.d.Verify(ctx, 1000, nop, nop); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("empty ledger: %v", err)
	}
}

func TestAdoptionFailures(t *testing.T) {
	r := newRig(t)
	r.sensor.add(1000, 2)
	r.sensor.failDB = errors.New("db broken")
	if err := r.d.Warm(); err == nil {
		t.Fatal("adopted from a broken database")
	}
	if _, exists, _ := trust.LoadLedger(r.d.cfg.LedgerPath); exists {
		t.Fatal("a ledger was written from a failed adoption")
	}
	r.sensor.failDB = nil
	r.sensor.noStorage = true
	if err := r.d.Warm(); err != nil {
		t.Fatalf("adoption from an empty database: %v", err)
	}
	if l, exists, _ := trust.LoadLedger(r.d.cfg.LedgerPath); !exists || len(l.Entries()) != 0 {
		t.Fatal("empty database did not give an empty ledger")
	}
}
