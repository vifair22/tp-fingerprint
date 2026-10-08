package validity

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// LED programs (command 0x39) the reference sends around a scan. The
// layout is not understood; they are replayed as captured.
var (
	glowStart = mustHex("3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	glowEnd   = mustHex("39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
)

// Interrupt types seen during a capture.
const (
	intCaptureStart  = 0
	intFingerDown    = 2
	intCaptureUpdate = 3
	// In an update interrupt, this bit of byte 2 says the capture is done.
	captureDoneBit = 4
)

// ErrScan is a capture the sensor rejected (finger moved, partial
// touch). Enrollment and identification retry it.
var ErrScan = errors.New("scan failed")

// ErrNoMatch means the finger matched nothing enrolled.
var ErrNoMatch = errors.New("finger not recognised")

// Glow lights the sensor's LED for a scan, or turns it back off.
func (s *Sensor) Glow(on bool) error {
	prog := glowEnd
	if on {
		prog = glowStart
	}
	_, err := s.sess.CmdOK(prog)
	return err
}

// capture is the reference's capture(): start a capture, wait for the
// finger and the end of the scan, and read the result. The sensor is told
// to stop (command 0x04) however it ends.
func (s *Sensor) capture(ctx context.Context, mode CaptureMode) (err error) {
	defer func() {
		// "capture stop if still running, cleanup"; its reply does not
		// matter.
		_, _, _ = s.sess.Cmd([]byte{0x04})
	}()
	cmd, err := s.buildCmd02(mode)
	if err != nil {
		return err
	}
	if _, err := s.sess.CmdOK(cmd); err != nil {
		return fmt.Errorf("start capture: %w", err)
	}
	b, err := s.sess.link.WaitInt(ctx)
	if err != nil {
		return err
	}
	if len(b) == 0 || b[0] != intCaptureStart {
		return fmt.Errorf("capture start: unexpected interrupt %x", b)
	}
	for {
		if b, err = s.sess.link.WaitInt(ctx); err != nil {
			return err
		}
		if len(b) > 0 && b[0] == intFingerDown {
			break
		}
	}
	for {
		if b, err = s.sess.link.WaitInt(ctx); err != nil {
			return err
		}
		if len(b) < 3 || b[0] != intCaptureUpdate {
			return fmt.Errorf("%w: unexpected interrupt %x", ErrScan, b)
		}
		if b[2]&captureDoneBit != 0 {
			break
		}
	}
	p, err := s.sess.CmdOK([]byte{0x51, 0x00, 0x20, 0x00, 0x00})
	if err != nil {
		return fmt.Errorf("capture result: %w", err)
	}
	if len(p) < 4 || int(binary.LittleEndian.Uint32(p)) != len(p)-4 || len(p)-4 < 12 {
		return fmt.Errorf("capture result: %d bytes: %w", len(p), ErrShortReply)
	}
	if code := binary.LittleEndian.Uint32(p[12:]); code != 0 {
		return fmt.Errorf("%w: sensor error 0x%04x", ErrScan, code)
	}
	return nil
}

// --- enrollment ---

// EnrollEvent reports one touch during enrollment: either progress (Err
// nil) or a rejected touch to be repeated.
type EnrollEvent struct {
	Touch int // touches accepted so far
	Err   error
}

// maxEnrollFailures bounds consecutive rejected touches. The reference
// retries forever.
const maxEnrollFailures = 10

// ErrEnrollAborted means enrollment gave up after too many rejected
// touches in a row.
var ErrEnrollAborted = errors.New("enrollment abandoned after repeated failed touches")

// enrollMagicLen is the header length of each block in an enrollment
// update reply, "hardcoded in the DLL".
const enrollMagicLen = 0x38

// appendNewImage is append_new_image: submit the previous template and
// read back the new header, template and template id. tid is empty until
// the sensor considers the enrollment complete.
func (s *Sensor) appendNewImage(ctx context.Context, prev []byte) (template, tid []byte, err error) {
	if _, err := s.enrollmentUpdate(prev); err != nil {
		return nil, nil, err
	}
	if _, err := s.sess.link.WaitInt(ctx); err != nil {
		return nil, nil, err
	}
	p, err := s.enrollmentUpdate(prev)
	if err != nil {
		return nil, nil, err
	}
	if len(p) < 2 || int(binary.LittleEndian.Uint16(p)) != len(p)-2 {
		return nil, nil, fmt.Errorf("enrollment update: %d bytes: %w", len(p), ErrShortReply)
	}
	p = p[2:]
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, nil, fmt.Errorf("enrollment update: %d-byte block header: %w", len(p), ErrShortReply)
		}
		tag, n := binary.LittleEndian.Uint16(p), int(binary.LittleEndian.Uint16(p[2:]))
		if len(p) < enrollMagicLen+n {
			return nil, nil, fmt.Errorf("enrollment update: block %d: %w", tag, ErrShortReply)
		}
		switch tag {
		case 0:
			template = append([]byte(nil), p[:enrollMagicLen+n]...)
		case 3:
			tid = append([]byte(nil), p[enrollMagicLen:enrollMagicLen+n]...)
		case 1:
			// a header the reference passes to its progress callback
			// and nothing else reads
		default:
			s.sess.link.log.Warn("ignoring unknown enrollment block", "tag", tag)
		}
		p = p[enrollMagicLen+n:]
	}
	return template, tid, nil
}

// enrollmentUpdate is command 0x6b, which writes flash.
func (s *Sensor) enrollmentUpdate(prev []byte) ([]byte, error) {
	if _, err := s.sess.CmdOK(blobDBWriteEnable); err != nil {
		return nil, fmt.Errorf("write enable: %w", err)
	}
	var p []byte
	err := withCleanups(s.sess, func() error {
		var err error
		p, err = s.sess.CmdOK(concat([]byte{0x6b}, prev))
		return err
	})
	return p, err
}

func (s *Sensor) enrollmentEnd() {
	// The reference asserts this status but only inside a finally that
	// would mask the real error; a failure here is logged.
	if _, err := s.sess.CmdOK([]byte{0x69, 0, 0, 0, 0}); err != nil {
		s.sess.link.log.Warn("ending enrollment update", "err", err)
	}
}

// ParseFingerData reads a finger record's value as fingerData lays it
// out, returning the finger and the template id.
func ParseFingerData(v []byte) (subtype uint16, tid []byte, err error) {
	bad := fmt.Errorf("finger record: %d bytes: %w", len(v), ErrShortReply)
	if len(v) < 12 || binary.LittleEndian.Uint16(v[8:]) != 1 {
		return 0, nil, bad
	}
	subtype = binary.LittleEndian.Uint16(v)
	tl := int(binary.LittleEndian.Uint16(v[10:]))
	rest := v[12:]
	if len(rest) < tl+4 || binary.LittleEndian.Uint16(rest[tl:]) != 2 {
		return 0, nil, bad
	}
	il := int(binary.LittleEndian.Uint16(rest[tl+2:]))
	rest = rest[tl+4:]
	if len(rest) < il {
		return 0, nil, bad
	}
	return subtype, append([]byte(nil), rest[:il]...), nil
}

// fingerData is make_finger_data: the finger record's value.
func fingerData(subtype uint16, template, tid []byte) []byte {
	t := concat(u16le(1, len(template)), template)
	t = concat(t, u16le(2, len(tid)), tid)
	out := concat(u16le(int(subtype), 3, len(t), 0x20), t)
	return append(out, make([]byte, 0x20)...)
}

func u16le(vs ...int) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint16(b, uint16(v))
	}
	return b
}

// Enroll enrolls a finger for sid, as the reference's enroll(): touches
// are captured until the sensor reports a complete template, then the
// user record (created if needed) gets a finger record. progress, if not
// nil, is called after every touch. It returns the finger record's id.
//
// It returns the finger record's id and the template id (tid) the sensor
// gave the template, which a match later reports; the host keeps it to
// recognise its own enrollments (docs/DESIGN.md, finding F2).
func (s *Sensor) Enroll(ctx context.Context, sid SID, subtype uint16, progress func(EnrollEvent)) (uint16, []byte, error) {
	db := NewDB(s.sess)
	stg, err := db.EnsureStorage()
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.sess.CmdOK([]byte{0x69, 1, 0, 0, 0}); err != nil {
		return 0, nil, fmt.Errorf("start enrollment: %w", err)
	}
	var (
		key      uint32
		template []byte
		tid      []byte
		touches  int
		failures int
	)
	for len(tid) == 0 {
		err := s.enrollTouch(ctx, &key, &template, &tid)
		s.enrollmentEnd()
		switch {
		case err == nil:
			touches++
			failures = 0
			if progress != nil {
				progress(EnrollEvent{Touch: touches})
			}
		case ctx.Err() != nil:
			_ = s.Glow(false)
			return 0, nil, ctx.Err()
		case !retryable(err):
			_ = s.Glow(false)
			return 0, nil, err
		default:
			failures++
			if progress != nil {
				progress(EnrollEvent{Touch: touches, Err: err})
			}
			if failures >= maxEnrollFailures {
				_ = s.Glow(false)
				return 0, nil, fmt.Errorf("%w: %w", ErrEnrollAborted, err)
			}
		}
	}
	// "done twice for some reason"
	s.enrollmentEnd()

	user, err := db.LookupUser(stg.ID, sid)
	if err != nil {
		return 0, nil, err
	}
	var uid uint16
	if user != nil {
		uid = user.ID
	} else if uid, err = db.NewUser(stg.ID, sid); err != nil {
		return 0, nil, err
	}
	fid, err := db.NewFinger(stg.ID, uid, fingerData(subtype, template, tid))
	if err != nil {
		return 0, nil, err
	}
	if _, err := s.sess.link.WaitInt(ctx); err != nil {
		return 0, nil, err
	}
	return fid, tid, s.Glow(false)
}

// enrollTouch is one pass of the enrollment loop: light, capture, start
// the update and append the image.
func (s *Sensor) enrollTouch(ctx context.Context, key *uint32, template, tid *[]byte) error {
	if err := s.Glow(true); err != nil {
		return err
	}
	if err := s.capture(ctx, ModeEnroll); err != nil {
		return err
	}
	req := binary.LittleEndian.AppendUint32([]byte{0x68}, *key)
	p, err := s.sess.CmdOK(binary.LittleEndian.AppendUint32(req, 0))
	if err != nil {
		return fmt.Errorf("enrollment update start: %w", err)
	}
	if len(p) < 4 {
		return fmt.Errorf("enrollment update start: %d bytes: %w", len(p), ErrShortReply)
	}
	*key = binary.LittleEndian.Uint32(p)
	if _, err := s.sess.link.WaitInt(ctx); err != nil {
		return err
	}
	t, id, err := s.appendNewImage(ctx, *template)
	if err != nil {
		return err
	}
	*template, *tid = t, id
	return nil
}

// retryable says whether a failed touch should be retried: a rejected
// scan or a sensor status. The reference retries every exception but USB
// errors and cancellation; this is narrower, so a malformed reply stops
// the loop instead of repeating it.
func retryable(err error) bool {
	var se *StatusError
	return errors.Is(err, ErrScan) || errors.As(err, &se)
}

// --- identification ---

// Match is a successful identification.
type Match struct {
	User    uint16 // user record id
	Subtype uint16 // which finger
	Hash    []byte
}

// identifyRetryDelay paces capture retries during identification, as the
// reference's sleep(1).
var identifyRetryDelay = time.Second

// Identify waits for a finger and matches it against every enrolled
// user, as the reference's identify(). Rejected scans are retried, each
// reported to retry if not nil, until ctx ends. ErrNoMatch means the
// finger is not enrolled.
func (s *Sensor) Identify(ctx context.Context, retry func(error)) (*Match, error) {
	for {
		if err := s.Glow(true); err != nil {
			return nil, err
		}
		err := s.capture(ctx, ModeIdentify)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !retryable(err) {
			_ = s.Glow(false)
			return nil, err
		}
		if retry != nil {
			retry(err)
		}
		select {
		case <-ctx.Done():
			_ = s.Glow(false)
			return nil, ctx.Err()
		case <-time.After(identifyRetryDelay):
		}
	}
	m, err := s.match(ctx)
	if gerr := s.Glow(false); err == nil {
		err = gerr
	}
	return m, err
}

// match is match_finger: compare the captured finger against any user in
// any storage, then fetch the result. Command 0x62 cleans up whatever
// happened.
func (s *Sensor) match(ctx context.Context) (*Match, error) {
	// Clean up before as well as after. Until 0x62 runs, 0x60 keeps
	// returning the last match (seen on the real sensor), so a cleanup
	// that never arrived must not leave an old result to be read.
	_, _, _ = s.sess.Cmd([]byte{0x62, 0, 0, 0, 0})
	defer func() { _, _, _ = s.sess.Cmd([]byte{0x62, 0, 0, 0, 0}) }()
	req := []byte{0x5e, 2, 0xff}
	req = append(req, u16le(0, 0, 1, 0, 0)...) // storage 0, user 0: any
	if _, err := s.sess.CmdOK(req); err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	b, err := s.sess.link.WaitInt(ctx)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || b[0] != intCaptureUpdate {
		return nil, fmt.Errorf("%w (interrupt %s)", ErrNoMatch, hex.EncodeToString(b))
	}
	p, err := s.sess.CmdOK([]byte{0x60, 0, 0, 0, 0})
	if err != nil {
		return nil, fmt.Errorf("match result: %w", err)
	}
	if len(p) < 2 || int(binary.LittleEndian.Uint16(p)) != len(p)-2 {
		return nil, fmt.Errorf("match result: %d bytes: %w", len(p), ErrShortReply)
	}
	fields := map[uint16][]byte{}
	for p = p[2:]; len(p) > 0; {
		if len(p) < 4 {
			return nil, fmt.Errorf("match result: %w", ErrShortReply)
		}
		t, n := binary.LittleEndian.Uint16(p), int(binary.LittleEndian.Uint16(p[2:]))
		if len(p)-4 < n {
			return nil, fmt.Errorf("match result: field %d: %w", t, ErrShortReply)
		}
		fields[t] = p[4 : 4+n]
		p = p[4+n:]
	}
	usr, sub := fields[1], fields[3]
	if len(usr) < 4 || len(sub) < 2 {
		return nil, errors.New("match result: no user or finger field")
	}
	return &Match{
		User:    uint16(binary.LittleEndian.Uint32(usr)),
		Subtype: binary.LittleEndian.Uint16(sub),
		Hash:    append([]byte(nil), fields[4]...),
	}, nil
}
