// Package fprint serves the part of fprintd's D-Bus API (net.reactivated.Fprint)
// that Plasma's System Settings uses to list, enroll and delete fingers, on
// top of fpd's sensor. Authentication stays with pam_fpd.so; this API has no
// verify.
//
// The calls and statuses were taken from plasma-workspace 6.7.5's Users KCM
// (kcms/users/src) and fprintd's interface description; docs/DESIGN.md,
// "Phase 2", lists them.
package fprint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"git.airies.net/vifair22/t480-fingerprint/internal/server"
	"git.airies.net/vifair22/t480-fingerprint/internal/validity"
)

// Bus names and paths, as fprintd uses them.
const (
	BusName                     = "net.reactivated.Fprint"
	ManagerPath dbus.ObjectPath = "/net/reactivated/Fprint/Manager"
	DevicePath  dbus.ObjectPath = "/net/reactivated/Fprint/Device/0"

	managerIface = "net.reactivated.Fprint.Manager"
	deviceIface  = "net.reactivated.Fprint.Device"
	errPrefix    = "net.reactivated.Fprint.Error."
)

// EnrollStages is what num-enroll-stages reports while the device is
// claimed. The sensor decides how many touches it needs (11 in the first
// enrollment); stage signals stop one short of this and completion fills
// the progress, so it never overshoots.
const EnrollStages = 12

// Gate hands out the sensor on the same terms as fpd's socket: at once or
// not at all. server.Server implements it.
type Gate interface {
	Acquire() (release func(), ok bool)
}

// Service is the fprintd API on one bus connection.
type Service struct {
	conn   *dbus.Conn
	reader server.Reader
	gate   Gate
	log    *slog.Logger
	props  *prop.Properties

	// uidOf asks the bus which uid owns a connection; lookup resolves a
	// user name. Both are swapped in tests.
	uidOf  func(sender string) (uint32, error)
	lookup func(name string) (uint32, error)

	mu     sync.Mutex
	claim  *claim
	enroll *enrollment
}

// claim is who holds the device, for whom.
type claim struct {
	sender string
	uid    uint32
}

// enrollment is one running EnrollStart.
type enrollment struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a Service over conn. lookup resolves user names to uids.
func New(conn *dbus.Conn, r server.Reader, g Gate, log *slog.Logger, lookup func(string) (uint32, error)) *Service {
	s := &Service{conn: conn, reader: r, gate: g, log: log, lookup: lookup}
	s.uidOf = func(sender string) (uint32, error) {
		var uid uint32
		err := conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, sender).Store(&uid)
		return uid, err
	}
	return s
}

// Start exports the objects and takes the bus name. It fails if the name
// is taken (fprintd running, or a second fpd).
func (s *Service) Start() error {
	var err error
	s.props, err = prop.Export(s.conn, DevicePath, prop.Map{deviceIface: {
		"name":              {Value: "Synaptics 06cb:009a (fpd)", Emit: prop.EmitConst},
		"num-enroll-stages": {Value: int32(-1), Emit: prop.EmitTrue},
		"scan-type":         {Value: "press", Emit: prop.EmitConst},
		"finger-present":    {Value: false, Emit: prop.EmitTrue},
		"finger-needed":     {Value: false, Emit: prop.EmitTrue},
	}})
	if err != nil {
		return err
	}
	if err := s.conn.Export(&manager{}, ManagerPath, managerIface); err != nil {
		return err
	}
	if err := s.conn.Export(&device{s}, DevicePath, deviceIface); err != nil {
		return err
	}
	for path, node := range map[dbus.ObjectPath]*introspect.Node{
		ManagerPath: {Name: string(ManagerPath), Interfaces: []introspect.Interface{introspect.IntrospectData, managerIntrospection}},
		DevicePath: {Name: string(DevicePath), Interfaces: []introspect.Interface{
			introspect.IntrospectData, prop.IntrospectData, s.deviceIntrospection()}},
	} {
		if err := s.conn.Export(introspect.NewIntrospectable(node), path, "org.freedesktop.DBus.Introspectable"); err != nil {
			return err
		}
	}
	// A claimant that leaves the bus loses its claim, as with fprintd.
	if err := s.conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		return err
	}
	ch := make(chan *dbus.Signal, 16)
	s.conn.Signal(ch)
	go s.watchOwners(ch)

	reply, err := s.conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("%s is already owned (is fprintd running?)", BusName)
	}
	return nil
}

// Close stops any enrollment and gives up the name.
func (s *Service) Close() {
	s.mu.Lock()
	e := s.enroll
	s.mu.Unlock()
	if e != nil {
		e.cancel()
		<-e.done
	}
	_, _ = s.conn.ReleaseName(BusName)
}

func (s *Service) watchOwners(ch <-chan *dbus.Signal) {
	for sig := range ch {
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) != 3 {
			continue
		}
		name, _ := sig.Body[0].(string)
		newOwner, _ := sig.Body[2].(string)
		if newOwner != "" {
			continue
		}
		s.mu.Lock()
		gone := s.claim != nil && s.claim.sender == name
		s.mu.Unlock()
		if gone {
			s.log.Info("claimant left the bus; releasing the device", "sender", name)
			s.release()
		}
	}
}

// fprintd's errors.
func fpErr(name, msg string) *dbus.Error {
	return &dbus.Error{Name: errPrefix + name, Body: []any{msg}}
}

var (
	errNotClaimed  = fpErr("ClaimDevice", "Device was not claimed before use")
	errInUse       = fpErr("AlreadyInUse", "Device was already claimed")
	errBusy        = fpErr("AlreadyInUse", "The fingerprint reader is busy")
	errDenied      = fpErr("PermissionDenied", "Not allowed to act for that user")
	errNoPrints    = fpErr("NoEnrolledPrints", "No fingerprints enrolled")
	errNoAction    = fpErr("NoActionInProgress", "No enrollment in progress")
	errBadFinger   = fpErr("InvalidFingername", "Invalid finger name")
	errUnavailable = fpErr("Internal", "The fingerprint reader is unavailable")
)

func internal(err error) *dbus.Error { return fpErr("Internal", err.Error()) }

// target resolves the user a call is about and checks the caller may act
// for them: anyone for themselves, root for anyone. An empty name means the
// caller.
func (s *Service) target(sender dbus.Sender, username string) (uint32, *dbus.Error) {
	caller, err := s.uidOf(string(sender))
	if err != nil {
		return 0, internal(fmt.Errorf("who is calling: %w", err))
	}
	if username == "" {
		return caller, nil
	}
	uid, err := s.lookup(username)
	if err != nil {
		return 0, fpErr("Internal", fmt.Sprintf("no such user %q", username))
	}
	if caller != 0 && caller != uid {
		return 0, errDenied
	}
	return uid, nil
}

// claimed returns the claim if sender holds it.
func (s *Service) claimed(sender dbus.Sender) (*claim, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claim == nil || s.claim.sender != string(sender) {
		return nil, errNotClaimed
	}
	c := *s.claim
	return &c, nil
}

// withSensor runs fn holding the sensor, or reports it busy.
func (s *Service) withSensor(fn func() error) *dbus.Error {
	release, ok := s.gate.Acquire()
	if !ok {
		return errBusy
	}
	defer release()
	return mapErr(fn())
}

func mapErr(err error) *dbus.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, server.ErrNotEnrolled):
		return errNoPrints
	case errors.Is(err, server.ErrUnavailable):
		return errUnavailable
	}
	return internal(err)
}

// release drops the claim, stopping any enrollment first.
func (s *Service) release() {
	s.mu.Lock()
	e := s.enroll
	s.mu.Unlock()
	if e != nil {
		e.cancel()
		<-e.done
	}
	s.mu.Lock()
	s.claim = nil
	s.mu.Unlock()
	s.props.SetMust(deviceIface, "num-enroll-stages", int32(-1))
}

// manager is net.reactivated.Fprint.Manager.
type manager struct{}

func (*manager) GetDevices() ([]dbus.ObjectPath, *dbus.Error) {
	return []dbus.ObjectPath{DevicePath}, nil
}

func (*manager) GetDefaultDevice() (dbus.ObjectPath, *dbus.Error) {
	return DevicePath, nil
}

// device is net.reactivated.Fprint.Device. Its exported methods are the
// interface's; the Service holds the state.
type device struct{ s *Service }

func (d *device) ListEnrolledFingers(sender dbus.Sender, username string) ([]string, *dbus.Error) {
	uid, derr := d.s.target(sender, username)
	if derr != nil {
		return nil, derr
	}
	var names []string
	derr = d.s.withSensor(func() error {
		fingers, err := d.s.reader.List(uid)
		for _, f := range fingers {
			names = append(names, validity.FingerName(f.Subtype))
		}
		return err
	})
	if derr != nil {
		return nil, derr
	}
	if len(names) == 0 {
		return nil, errNoPrints
	}
	return names, nil
}

func (d *device) Claim(sender dbus.Sender, username string) *dbus.Error {
	uid, derr := d.s.target(sender, username)
	if derr != nil {
		return derr
	}
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	if d.s.claim != nil {
		return errInUse
	}
	d.s.claim = &claim{sender: string(sender), uid: uid}
	d.s.props.SetMust(deviceIface, "num-enroll-stages", int32(EnrollStages))
	d.s.log.Info("device claimed", "sender", sender, "for", uid)
	return nil
}

func (d *device) Release(sender dbus.Sender) *dbus.Error {
	if _, derr := d.s.claimed(sender); derr != nil {
		return derr
	}
	d.s.release()
	return nil
}

func (d *device) DeleteEnrolledFingers(sender dbus.Sender, username string) *dbus.Error {
	uid, derr := d.s.target(sender, username)
	if derr != nil {
		return derr
	}
	return d.s.withSensor(func() error { return d.s.reader.Delete(uid, 0) })
}

func (d *device) DeleteEnrolledFingers2(sender dbus.Sender) *dbus.Error {
	c, derr := d.s.claimed(sender)
	if derr != nil {
		return derr
	}
	return d.s.withSensor(func() error { return d.s.reader.Delete(c.uid, 0) })
}

func (d *device) DeleteEnrolledFinger(sender dbus.Sender, finger string) *dbus.Error {
	c, derr := d.s.claimed(sender)
	if derr != nil {
		return derr
	}
	sub, ok := validity.FingerSubtype(finger)
	if !ok {
		return errBadFinger
	}
	return d.s.withSensor(func() error { return d.s.reader.Delete(c.uid, sub) })
}

func (d *device) EnrollStart(sender dbus.Sender, finger string) *dbus.Error {
	c, derr := d.s.claimed(sender)
	if derr != nil {
		return derr
	}
	sub, ok := validity.FingerSubtype(finger)
	if !ok {
		return errBadFinger
	}
	release, ok := d.s.gate.Acquire()
	if !ok {
		return errBusy
	}
	d.s.mu.Lock()
	if d.s.enroll != nil {
		d.s.mu.Unlock()
		release()
		return errInUse
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &enrollment{cancel: cancel, done: make(chan struct{})}
	d.s.enroll = e
	d.s.mu.Unlock()
	go d.s.runEnroll(ctx, e, release, c.uid, sub)
	return nil
}

func (d *device) EnrollStop(sender dbus.Sender) *dbus.Error {
	if _, derr := d.s.claimed(sender); derr != nil {
		return derr
	}
	d.s.mu.Lock()
	e := d.s.enroll
	d.s.mu.Unlock()
	if e == nil {
		return errNoAction
	}
	e.cancel()
	<-e.done
	return nil
}

func (s *Service) status(result string, done bool) {
	if err := s.conn.Emit(DevicePath, deviceIface+".EnrollStatus", result, done); err != nil {
		s.log.Warn("emitting EnrollStatus", "err", err)
	}
}

// runEnroll enrolls, signalling progress the way fprintd does. A finger that
// is already enrolled is replaced, as fprintd replaces it.
func (s *Service) runEnroll(ctx context.Context, e *enrollment, release func(), uid uint32, sub uint16) {
	defer func() {
		s.props.SetMust(deviceIface, "finger-needed", false)
		release()
		s.mu.Lock()
		s.enroll = nil
		s.mu.Unlock()
		close(e.done)
	}()
	s.log.Info("enrolling over D-Bus", "for", uid, "finger", validity.FingerName(sub))
	err := s.reader.Delete(uid, sub)
	if err != nil && !errors.Is(err, server.ErrNotEnrolled) {
		s.status(statusFor(err), true)
		return
	}
	err = s.reader.Enroll(ctx, uid, sub,
		func() { s.props.SetMust(deviceIface, "finger-needed", true) },
		func(touches int, err error) {
			switch {
			case err != nil:
				s.status("enroll-retry-scan", false)
			case touches < EnrollStages:
				s.status("enroll-stage-passed", false)
			}
		})
	switch {
	case ctx.Err() != nil:
		// EnrollStop or Release: fprintd reports nothing more.
	case err != nil:
		s.log.Warn("enrollment failed", "err", err)
		s.status(statusFor(err), true)
	default:
		s.status("enroll-completed", true)
	}
}

func statusFor(err error) string {
	if errors.Is(err, server.ErrUnavailable) {
		return "enroll-disconnected"
	}
	return "enroll-failed"
}

var managerIntrospection = introspect.Interface{
	Name: managerIface,
	Methods: []introspect.Method{
		{Name: "GetDevices", Args: []introspect.Arg{{Name: "devices", Type: "ao", Direction: "out"}}},
		{Name: "GetDefaultDevice", Args: []introspect.Arg{{Name: "device", Type: "o", Direction: "out"}}},
	},
}

func (s *Service) deviceIntrospection() introspect.Interface {
	in := func(name, typ string) introspect.Arg { return introspect.Arg{Name: name, Type: typ, Direction: "in"} }
	return introspect.Interface{
		Name: deviceIface,
		Methods: []introspect.Method{
			{Name: "ListEnrolledFingers", Args: []introspect.Arg{in("username", "s"),
				{Name: "enrolled_fingers", Type: "as", Direction: "out"}}},
			{Name: "DeleteEnrolledFingers", Args: []introspect.Arg{in("username", "s")}},
			{Name: "DeleteEnrolledFingers2"},
			{Name: "DeleteEnrolledFinger", Args: []introspect.Arg{in("finger_name", "s")}},
			{Name: "Claim", Args: []introspect.Arg{in("username", "s")}},
			{Name: "Release"},
			{Name: "EnrollStart", Args: []introspect.Arg{in("finger_name", "s")}},
			{Name: "EnrollStop"},
		},
		Signals: []introspect.Signal{
			{Name: "EnrollStatus", Args: []introspect.Arg{{Name: "result", Type: "s"}, {Name: "done", Type: "b"}}},
		},
		Properties: s.props.Introspection(deviceIface),
	}
}
