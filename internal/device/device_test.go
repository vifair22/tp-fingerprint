package device

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
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
}

func newFake() *fakeSensor { return &fakeSensor{users: map[uint16]*validity.User{}, nextID: 10} }

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

func (f *fakeSensor) Identify(ctx context.Context, retry func(error)) (*validity.Match, error) {
	retry(validity.ErrScan)
	return f.scan()
}

func (f *fakeSensor) Enroll(_ context.Context, sid validity.SID, subtype uint16, progress func(validity.EnrollEvent)) (uint16, error) {
	progress(validity.EnrollEvent{Touch: 1})
	uid, _ := sid.UID()
	u, _ := f.LookupUser(0, sid)
	if u == nil {
		u = f.add(uid)
	}
	u.Fingers = append(u.Fingers, validity.Finger{ID: f.nextID, Subtype: subtype})
	f.nextID++
	return f.nextID - 1, nil
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
}

func newRig() *rig {
	r := &rig{at: usbfs.Info{Bus: 1, Addr: 5}, sensor: newFake()}
	r.d = &Device{cfg: Config{Log: slog.New(slog.DiscardHandler)}}
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
		return r.sensor, nil
	}
	return r
}

func nop()              {}
func nopErr(int, error) {}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	r := newRig()
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
	r := newRig()
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

	// A USB-level failure drops the session; the next request reopens.
	r.sensor.scan = func() (*validity.Match, error) { return nil, usbfs.ErrDisconnected }
	if _, err := r.d.Verify(ctx, 1000, nop, nop); !errors.Is(err, usbfs.ErrDisconnected) {
		t.Fatalf("usb failure: %v", err)
	}
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: me.ID}, nil }
	if ok, _ := r.d.Verify(ctx, 1000, nop, nop); !ok || r.opens != 3 {
		t.Fatalf("after the drop: match %v, opens %d", ok, r.opens)
	}

	// Rejected scans and cancellation keep the session.
	for _, keep := range []error{validity.ErrScan, validity.ErrEnrollAborted} {
		r.sensor.scan = func() (*validity.Match, error) { return nil, keep }
		r.d.Verify(ctx, 1000, nop, nop)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	r.sensor.scan = func() (*validity.Match, error) { return nil, c.Err() }
	r.d.Verify(c, 1000, nop, nop)
	if r.opens != 3 {
		t.Fatalf("session dropped for a benign outcome (%d opens)", r.opens)
	}

	// A sensor that is not on the bus is unavailable, and so is one that
	// will not open.
	r.gone = true
	if _, err := r.d.Verify(ctx, 1000, nop, nop); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("missing sensor: %v", err)
	}
	r.gone = false
	r.openErr = errors.New("handshake failed")
	if _, err := r.d.Verify(ctx, 1000, nop, nop); !errors.Is(err, server.ErrUnavailable) {
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
	r := newRig()
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
	r.sensor.scan = func() (*validity.Match, error) { return &validity.Match{User: 999}, nil }
	if _, _, err := r.d.Identify(ctx, nop, nop); err == nil {
		t.Error("match on a missing record")
	}
	r.sensor.scan = func() (*validity.Match, error) { return nil, errors.New("usb") }
	if _, _, err := r.d.Identify(ctx, nop, nop); err == nil {
		t.Error("scan failure swallowed")
	}
	r.gone = true
	if _, _, err := r.d.Identify(ctx, nop, nop); !errors.Is(err, server.ErrUnavailable) {
		t.Errorf("missing sensor: %v", err)
	}
}

func TestEnrollListDelete(t *testing.T) {
	ctx := context.Background()
	r := newRig()
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
	if _, err := d.Verify(context.Background(), 1, nop, nop); !errors.Is(err, server.ErrUnavailable) {
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
