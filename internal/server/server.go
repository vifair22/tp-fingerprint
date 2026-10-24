// Package server is fpd's socket server: it authenticates callers by
// their socket credentials, runs one sensor operation at a time, and
// translates between the protocol and a Reader.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"git.airies.net/vifair22/tp-fingerprint/internal/proto"
)

// Enrolled is one enrolled finger.
type Enrolled struct {
	UID     uint32
	Subtype uint16
}

// Errors a Reader returns that map to specific results.
var (
	ErrNotEnrolled = errors.New("nothing enrolled")
	ErrExists      = errors.New("finger already enrolled")
	ErrUnavailable = errors.New("sensor unavailable")
)

// Reader is the sensor as fpd uses it. Calls are never concurrent.
type Reader interface {
	// Verify scans one finger and reports whether it is one of uid's.
	// It returns ErrNotEnrolled, before waiting for a finger, if uid has
	// nothing enrolled. retry is called for each unusable scan; prompt
	// once the sensor is ready for the finger.
	Verify(ctx context.Context, uid uint32, prompt, retry func()) (bool, error)
	// Identify scans one finger and reports whose it is, if anyone's.
	Identify(ctx context.Context, prompt, retry func()) (Enrolled, bool, error)
	// Enroll enrolls a finger, calling progress after every touch.
	Enroll(ctx context.Context, uid uint32, subtype uint16, prompt func(), progress func(touches int, err error)) error
	// List returns uid's fingers, or everyone's for proto.AllUsers.
	List(uid uint32) ([]Enrolled, error)
	// Delete deletes one finger, or all of uid's for subtype 0.
	Delete(uid uint32, subtype uint16) error
}

// Peer is who is on the other end of a connection.
type Peer struct {
	UID uint32
	PID int32
}

// Timeouts.
const (
	DefaultTimeout = 15 * time.Second
	MaxTimeout     = 2 * time.Minute
	enrollTimeout  = 5 * time.Minute
	requestTimeout = 5 * time.Second
)

// Server serves fpd's socket.
type Server struct {
	reader Reader
	log    *slog.Logger
	// remote reports whether pid belongs to a remote login session.
	remote func(pid int32) bool
	// peer reads the credentials of a connection.
	peer func(net.Conn) (Peer, error)

	busy sync.Mutex
	wg   sync.WaitGroup

	// Lockout (finding F5 in docs/DESIGN.md): consecutive non-matching
	// fingers per uid, and until when fingerprint is refused for it.
	lockMu sync.Mutex
	misses map[uint32]int
	locked map[uint32]time.Time
	now    func() time.Time
}

// Lockout policy: after LockoutMisses non-matching fingers in a row for a
// user, fingerprint is refused for LockoutFor (the password still works).
// Each resume gives the lock screen fresh tries, so without this an
// attacker with fake prints could keep trying by cycling the lid.
const (
	LockoutMisses = 5
	LockoutFor    = 30 * time.Minute
)

// lockedOut reports whether uid is locked out now.
func (s *Server) lockedOut(uid uint32) bool {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	until, ok := s.locked[uid]
	if ok && s.now().Before(until) {
		return true
	}
	delete(s.locked, uid)
	return false
}

// miss counts a non-matching finger for uid and reports whether that
// locked it out.
func (s *Server) miss(uid uint32) bool {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	s.misses[uid]++
	if s.misses[uid] < LockoutMisses {
		return false
	}
	s.misses[uid] = 0
	s.locked[uid] = s.now().Add(LockoutFor)
	return true
}

// matched clears uid's count of misses.
func (s *Server) matched(uid uint32) {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	delete(s.misses, uid)
}

// New returns a Server for r. remote decides whether a caller's session is
// remote; nil means none is.
func New(r Reader, log *slog.Logger, remote func(pid int32) bool) *Server {
	if remote == nil {
		remote = func(int32) bool { return false }
	}
	return &Server{reader: r, log: log, remote: remote, peer: peerCred,
		misses: map[uint32]int{}, locked: map[uint32]time.Time{}, now: time.Now}
}

// Serve accepts connections until ln is closed, then waits for the ones in
// flight. Their contexts derive from ctx.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer s.wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.handle(ctx, c)
		}()
	}
}

func peerCred(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if cerr != nil {
		return Peer{}, cerr
	}
	return Peer{UID: cred.Uid, PID: cred.Pid}, nil
}

// conn is one client: its events, and a context cancelled if it hangs up.
type conn struct {
	c    net.Conn
	peer Peer
	log  *slog.Logger
}

func (c *conn) send(typ uint16, payload []byte) {
	if err := proto.Write(c.c, typ, payload); err != nil {
		c.log.Debug("client gone", "err", err)
	}
}

func (c *conn) result(r uint32) {
	c.log.Info("result", "result", proto.ResultString(r))
	c.send(proto.EvResult, proto.U32s(r))
}

func (s *Server) handle(ctx context.Context, nc net.Conn) {
	peer, err := s.peer(nc)
	if err != nil {
		s.log.Warn("no peer credentials", "err", err)
		return
	}
	c := &conn{c: nc, peer: peer, log: s.log.With("uid", peer.UID, "pid", peer.PID)}
	_ = nc.SetReadDeadline(time.Now().Add(requestTimeout))
	req, err := proto.Read(nc)
	if err != nil {
		c.log.Warn("bad request", "err", err)
		c.result(proto.ResultBadRequest)
		return
	}
	_ = nc.SetReadDeadline(time.Time{})

	// The client sends nothing after its request, so a read returning
	// means it hung up: stop whatever is running for it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		var b [1]byte
		_, _ = nc.Read(b[:])
		cancel()
	}()

	switch req.Type {
	case proto.ReqVerify:
		s.verify(ctx, c, req)
	case proto.ReqIdentify:
		s.identify(ctx, c, req)
	case proto.ReqEnroll:
		s.enroll(ctx, c, req)
	case proto.ReqList:
		s.list(c, req)
	case proto.ReqDelete:
		s.delete(c, req)
	default:
		c.log.Warn("unknown request", "type", req.Type)
		c.result(proto.ResultBadRequest)
	}
}

// allowed applies the authorization rule: root may act for anyone, others
// only for themselves.
func allowed(p Peer, uid uint32) bool { return p.UID == 0 || p.UID == uid }

// Acquire takes the sensor for an in-process caller (the fprintd D-Bus
// service) on the same terms as a socket request: at once or not at all,
// so the two can never drive the sensor together.
func (s *Server) Acquire() (release func(), ok bool) {
	if !s.busy.TryLock() {
		return nil, false
	}
	return s.busy.Unlock, true
}

// claim takes the sensor, or reports BUSY: a second caller falls back to
// its password at once rather than waiting, as fprintd's claim does.
func (s *Server) claim(c *conn) bool {
	if !s.busy.TryLock() {
		c.result(proto.ResultBusy)
		return false
	}
	return true
}

// touchAllowed is the check for operations that need a finger on the
// sensor: not from a remote session.
func (s *Server) touchAllowed(c *conn) bool {
	if s.remote(c.peer.PID) {
		c.result(proto.ResultRemote)
		return false
	}
	return true
}

// withTimeout applies a request's timeout_ms: 0 is the default,
// proto.TimeoutNone none at all (the request lasts until the caller hangs
// up), anything else is capped at MaxTimeout.
func withTimeout(ctx context.Context, ms uint32) (context.Context, context.CancelFunc) {
	switch ms {
	case proto.TimeoutNone:
		return context.WithCancel(ctx)
	case 0:
		return context.WithTimeout(ctx, DefaultTimeout)
	}
	return context.WithTimeout(ctx, min(time.Duration(ms)*time.Millisecond, MaxTimeout))
}

// resultFor maps a Reader error to a result code.
func resultFor(ctx context.Context, err error) uint32 {
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return proto.ResultNotEnrolled
	case errors.Is(err, ErrExists):
		return proto.ResultExists
	case errors.Is(err, ErrUnavailable):
		return proto.ResultUnavailable
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return proto.ResultTimeout
	case ctx.Err() != nil:
		return proto.ResultCancelled
	}
	return proto.ResultError
}

func (s *Server) fail(ctx context.Context, c *conn, op string, err error) {
	r := resultFor(ctx, err)
	if r == proto.ResultError {
		c.log.Error(op+" failed", "err", err)
	}
	c.result(r)
}

func (s *Server) verify(ctx context.Context, c *conn, req proto.Frame) {
	v, err := req.Fields(4, 4, 4)
	if err != nil {
		c.result(proto.ResultBadRequest)
		return
	}
	uid, tries := v[0], max(v[2], 1)
	c.log.Info("verify", "for", uid, "tries", tries)
	if !allowed(c.peer, uid) {
		c.result(proto.ResultDenied)
		return
	}
	if !s.touchAllowed(c) {
		return
	}
	if s.lockedOut(uid) {
		c.log.Warn("fingerprint locked out after repeated misses", "for", uid)
		c.result(proto.ResultLockedOut)
		return
	}
	if !s.claim(c) {
		return
	}
	defer s.busy.Unlock()
	ctx, cancel := withTimeout(ctx, v[1])
	defer cancel()
	prompt := func() { c.send(proto.EvPrompt, nil) }
	retry := func() { c.send(proto.EvRetry, proto.U32s(proto.RetryScan)) }
	for try := uint32(1); ; try++ {
		ok, err := s.reader.Verify(ctx, uid, prompt, retry)
		switch {
		case err != nil:
			s.fail(ctx, c, "verify", err)
			return
		case ok:
			s.matched(uid)
			c.result(proto.ResultMatch)
			return
		}
		if s.miss(uid) {
			c.log.Warn("locking out fingerprint after repeated misses", "for", uid, "minutes", LockoutFor.Minutes())
			c.result(proto.ResultLockedOut)
			return
		}
		if try >= tries {
			c.result(proto.ResultNoMatch)
			return
		}
		c.send(proto.EvRetry, proto.U32s(proto.RetryNoMatch))
	}
}

func (s *Server) identify(ctx context.Context, c *conn, req proto.Frame) {
	v, err := req.Fields(4)
	if err != nil {
		c.result(proto.ResultBadRequest)
		return
	}
	// Says whose a finger is, so only root may ask.
	if c.peer.UID != 0 {
		c.result(proto.ResultDenied)
		return
	}
	if !s.touchAllowed(c) || !s.claim(c) {
		return
	}
	defer s.busy.Unlock()
	ctx, cancel := withTimeout(ctx, v[0])
	defer cancel()
	e, ok, err := s.reader.Identify(ctx, func() { c.send(proto.EvPrompt, nil) },
		func() { c.send(proto.EvRetry, proto.U32s(proto.RetryScan)) })
	switch {
	case err != nil:
		s.fail(ctx, c, "identify", err)
	case !ok:
		c.result(proto.ResultNoMatch)
	default:
		c.send(proto.EvFinger, proto.U16(proto.U32s(e.UID), e.Subtype))
		c.result(proto.ResultMatch)
	}
}

func (s *Server) enroll(ctx context.Context, c *conn, req proto.Frame) {
	v, err := req.Fields(4, 2)
	if err != nil || v[1] == 0 {
		c.result(proto.ResultBadRequest)
		return
	}
	uid, subtype := v[0], uint16(v[1])
	c.log.Info("enroll", "for", uid, "finger", subtype)
	if !allowed(c.peer, uid) {
		c.result(proto.ResultDenied)
		return
	}
	if !s.touchAllowed(c) || !s.claim(c) {
		return
	}
	defer s.busy.Unlock()
	ctx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()
	err = s.reader.Enroll(ctx, uid, subtype, func() { c.send(proto.EvPrompt, nil) },
		func(touches int, err error) {
			if err != nil {
				c.send(proto.EvRetry, proto.U32s(proto.RetryScan))
				return
			}
			c.send(proto.EvProgress, proto.U32s(uint32(touches)))
		})
	if err != nil {
		s.fail(ctx, c, "enroll", err)
		return
	}
	c.result(proto.ResultMatch)
}

func (s *Server) list(c *conn, req proto.Frame) {
	v, err := req.Fields(4)
	if err != nil {
		c.result(proto.ResultBadRequest)
		return
	}
	if !allowed(c.peer, v[0]) {
		c.result(proto.ResultDenied)
		return
	}
	if !s.claim(c) {
		return
	}
	defer s.busy.Unlock()
	fingers, err := s.reader.List(v[0])
	if err != nil {
		s.fail(context.Background(), c, "list", err)
		return
	}
	for _, f := range fingers {
		c.send(proto.EvFinger, proto.U16(proto.U32s(f.UID), f.Subtype))
	}
	c.result(proto.ResultMatch)
}

func (s *Server) delete(c *conn, req proto.Frame) {
	v, err := req.Fields(4, 2)
	if err != nil {
		c.result(proto.ResultBadRequest)
		return
	}
	if !allowed(c.peer, v[0]) {
		c.result(proto.ResultDenied)
		return
	}
	if !s.claim(c) {
		return
	}
	defer s.busy.Unlock()
	c.log.Info("delete", "for", v[0], "finger", v[1])
	if err := s.reader.Delete(v[0], uint16(v[1])); err != nil {
		s.fail(context.Background(), c, "delete", err)
		return
	}
	c.result(proto.ResultMatch)
}

// String names a peer in logs.
func (p Peer) String() string { return fmt.Sprintf("uid %d pid %d", p.UID, p.PID) }
