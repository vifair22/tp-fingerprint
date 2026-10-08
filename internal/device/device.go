// Package device is fpd's sensor: it keeps one session to the sensor open
// across requests, reopens it when the sensor has gone away (it
// re-enumerates after suspend), and maps users and fingers between the
// protocol and the sensor's database.
package device

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"git.airies.net/vifair22/t480-fingerprint/internal/atomicfile"
	"git.airies.net/vifair22/t480-fingerprint/internal/hostid"
	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
	"git.airies.net/vifair22/t480-fingerprint/internal/usbfs"
	"git.airies.net/vifair22/t480-fingerprint/internal/validity"
)

// sensor is what Device uses of an opened sensor: the database and the
// scans. The real one is opened by openReal; tests supply fakes.
type sensor interface {
	Storage() (*validity.Storage, error)
	LookupUser(storage uint16, sid validity.SID) (*validity.User, error)
	User(id uint16) (*validity.User, error)
	Users(*validity.Storage) ([]*validity.User, error)
	DeleteRecord(id uint16) error
	Identify(ctx context.Context, retry func(error)) (*validity.Match, error)
	Enroll(ctx context.Context, sid validity.SID, subtype uint16, progress func(validity.EnrollEvent)) (uint16, error)
	// Shutdown reboots the sensor, as the reference does on exit so that
	// it does not pile up TLS sessions, and releases the device.
	Shutdown() error
	// Close releases the device without telling the sensor anything.
	Close() error
}

// Config says where fpd's state lives.
type Config struct {
	SecretPath string
	CalibPath  string
	FwKey      *ecdsa.PublicKey
	Bus        usbfs.Bus
	Log        *slog.Logger
}

// Device implements server.Reader.
type Device struct {
	cfg Config
	// locate reports where the sensor is on the bus now; open opens it.
	locate func() (usbfs.Info, error)
	open   func(usbfs.Info) (sensor, error)

	mu     sync.Mutex
	cur    sensor
	at     usbfs.Info
	opened bool
}

// New returns a Device for the real sensor. Nothing is opened until the
// first request.
func New(cfg Config) *Device {
	d := &Device{cfg: cfg}
	d.locate = func() (usbfs.Info, error) {
		return cfg.Bus.Find(validity.VendorID, validity.ProductID)
	}
	d.open = d.openReal
	return d
}

// get returns an open sensor, reopening it if it is closed or the device
// has moved on the bus since it was opened.
func (d *Device) get() (sensor, error) {
	info, err := d.locate()
	if err != nil {
		d.drop()
		return nil, fmt.Errorf("%w: %w", server.ErrUnavailable, err)
	}
	if d.opened && info.Bus == d.at.Bus && info.Addr == d.at.Addr {
		return d.cur, nil
	}
	if d.opened {
		d.cfg.Log.Info("sensor moved on the bus, reopening", "bus", info.Bus, "addr", info.Addr)
		d.drop()
	}
	s, err := d.open(info)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", server.ErrUnavailable, err)
	}
	d.cur, d.at, d.opened = s, info, true
	d.cfg.Log.Info("sensor open", "bus", info.Bus, "addr", info.Addr)
	return s, nil
}

// drop forgets the open sensor; the next request reopens it.
func (d *Device) drop() {
	if !d.opened {
		return
	}
	if err := d.cur.Close(); err != nil {
		d.cfg.Log.Debug("closing a dropped sensor", "err", err)
	}
	d.cur, d.opened = nil, false
}

// settle keeps the session after outcomes that say nothing about its
// health, and drops it after anything else (a USB error, a sensor that
// stopped answering), so the next request starts from a clean open.
func (d *Device) settle(ctx context.Context, err error) error {
	switch {
	case err == nil,
		ctx.Err() != nil,
		errors.Is(err, validity.ErrNoMatch),
		errors.Is(err, validity.ErrScan),
		errors.Is(err, validity.ErrEnrollAborted),
		errors.Is(err, server.ErrNotEnrolled),
		errors.Is(err, server.ErrExists):
		return err
	}
	d.cfg.Log.Warn("dropping the sensor session", "err", err)
	d.drop()
	return err
}

// user finds uid's record, or ErrNotEnrolled.
func user(s sensor, uid uint32) (*validity.Storage, *validity.User, error) {
	stg, err := s.Storage()
	if errors.Is(err, validity.ErrNoStorage) {
		return nil, nil, server.ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	u, err := s.LookupUser(stg.ID, validity.UIDSID(uid))
	if err != nil {
		return nil, nil, err
	}
	if u == nil {
		return stg, nil, server.ErrNotEnrolled
	}
	return stg, u, nil
}

// Verify implements server.Reader.
func (d *Device) Verify(ctx context.Context, uid uint32, prompt, retry func()) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.get()
	if err != nil {
		return false, err
	}
	_, u, err := user(s, uid)
	if err == nil && len(u.Fingers) == 0 {
		err = server.ErrNotEnrolled
	}
	if err != nil {
		return false, d.settle(ctx, err)
	}
	prompt()
	m, err := s.Identify(ctx, func(error) { retry() })
	if errors.Is(err, validity.ErrNoMatch) {
		return false, nil
	}
	if err != nil {
		return false, d.settle(ctx, err)
	}
	return m.User == u.ID, nil
}

// Identify implements server.Reader.
func (d *Device) Identify(ctx context.Context, prompt, retry func()) (server.Enrolled, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.get()
	if err != nil {
		return server.Enrolled{}, false, err
	}
	prompt()
	m, err := s.Identify(ctx, func(error) { retry() })
	if errors.Is(err, validity.ErrNoMatch) {
		return server.Enrolled{}, false, nil
	}
	if err != nil {
		return server.Enrolled{}, false, d.settle(ctx, err)
	}
	u, err := s.User(m.User)
	if err != nil {
		return server.Enrolled{}, false, d.settle(ctx, err)
	}
	uid, ok := u.SID.UID()
	if !ok {
		// Enrolled by something that does not use our uid mapping.
		return server.Enrolled{}, false, nil
	}
	return server.Enrolled{UID: uid, Subtype: m.Subtype}, true, nil
}

// Enroll implements server.Reader.
func (d *Device) Enroll(ctx context.Context, uid uint32, subtype uint16, prompt func(), progress func(int, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.get()
	if err != nil {
		return err
	}
	_, u, err := user(s, uid)
	switch {
	case errors.Is(err, server.ErrNotEnrolled):
	case err != nil:
		return d.settle(ctx, err)
	default:
		for _, f := range u.Fingers {
			if f.Subtype == subtype {
				return server.ErrExists
			}
		}
	}
	prompt()
	_, err = s.Enroll(ctx, validity.UIDSID(uid), subtype, func(e validity.EnrollEvent) { progress(e.Touch, e.Err) })
	return d.settle(ctx, err)
}

// List implements server.Reader.
func (d *Device) List(uid uint32) ([]server.Enrolled, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx := context.Background()
	s, err := d.get()
	if err != nil {
		return nil, err
	}
	stg, err := s.Storage()
	if errors.Is(err, validity.ErrNoStorage) {
		return nil, nil
	}
	if err != nil {
		return nil, d.settle(ctx, err)
	}
	users, err := s.Users(stg)
	if err != nil {
		return nil, d.settle(ctx, err)
	}
	var out []server.Enrolled
	for _, u := range users {
		id, ok := u.SID.UID()
		if !ok || (uid != proto.AllUsers && id != uid) {
			continue
		}
		for _, f := range u.Fingers {
			out = append(out, server.Enrolled{UID: id, Subtype: f.Subtype})
		}
	}
	return out, nil
}

// Delete implements server.Reader.
func (d *Device) Delete(uid uint32, subtype uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx := context.Background()
	s, err := d.get()
	if err != nil {
		return err
	}
	_, u, err := user(s, uid)
	if err != nil {
		return d.settle(ctx, err)
	}
	if subtype == 0 {
		return d.settle(ctx, s.DeleteRecord(u.ID))
	}
	for _, f := range u.Fingers {
		if f.Subtype == subtype {
			return d.settle(ctx, s.DeleteRecord(f.ID))
		}
	}
	return server.ErrNotEnrolled
}

// Warm opens the sensor ahead of the first request, so that request does
// not pay for the handshake and calibration check.
func (d *Device) Warm() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.get()
	return err
}

// Close reboots the sensor if it is open and releases it.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.opened {
		return nil
	}
	err := d.cur.Shutdown()
	d.cur, d.opened = nil, false
	return err
}

// real is the opened hardware.
type real struct {
	*validity.DB
	*validity.Sensor
	sess *validity.Session
	dev  *usbfs.Device
}

func (r *real) Shutdown() error {
	err := validity.Reboot(r.sess)
	if cerr := r.dev.Close(); err == nil {
		err = cerr
	}
	return err
}

func (r *real) Close() error { return r.dev.Close() }

// openReal brings the sensor up as fpctl status does, then opens the
// sensor proper, calibrating if the saved data is missing or stale. It
// refuses a sensor without firmware: captures need it.
func (d *Device) openReal(info usbfs.Info) (sensor, error) {
	secret, err := hostid.Load(d.cfg.SecretPath)
	if err != nil {
		return nil, err
	}
	saved, err := os.ReadFile(d.cfg.CalibPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dev, err := usbfs.Open(d.cfg.Bus, info, 0)
	if err != nil {
		return nil, err
	}
	s, err := d.bringUp(dev, secret, saved)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return s, nil
}

func (d *Device) bringUp(dev *usbfs.Device, secret, saved []byte) (sensor, error) {
	link := validity.NewLink(dev, d.cfg.Log.With("sensor", true))
	sess, err := validity.Open(link, validity.DeriveHostKeys(secret), d.cfg.FwKey)
	if err != nil {
		return nil, err
	}
	fw, _, err := validity.GetFirmwareInfo(sess, validity.PartitionFwext)
	if err != nil {
		return nil, err
	}
	if fw == nil {
		return nil, errors.New("no firmware loaded (run fpctl upload-firmware)")
	}
	sen, err := validity.OpenSensor(sess, saved)
	if err != nil {
		return nil, err
	}
	did, err := sen.Calibrate(context.Background(), false)
	if err != nil {
		return nil, err
	}
	if did {
		d.cfg.Log.Info("calibrated the sensor")
		if err := atomicfile.Write(d.cfg.CalibPath, sen.CalibrationData(), 0o600); err != nil {
			return nil, err
		}
	}
	return &real{DB: validity.NewDB(sess), Sensor: sen, sess: sess, dev: dev}, nil
}
