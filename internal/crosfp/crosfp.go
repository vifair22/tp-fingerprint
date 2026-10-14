// Package crosfp speaks to a ChromeOS fingerprint MCU (FPMCU), such as the
// "bloonchipper" on the ThinkPad C14 Chromebook, through the kernel's
// cros_ec character device (/dev/cros_fp).
//
// The MCU is not a sensor the host drives: it captures, enrolls and matches
// on its own, and hands the host its templates encrypted under a key it
// derives from a seed the host sets once per MCU boot and a user context
// the host sets per session. The host stores the encrypted templates and
// uploads them again after every MCU reset. This package covers the
// commands that flow needs (the older seed and context scheme, not the
// GSC pairing one), and the fingerprint events the MCU raises.
//
// Command layouts and constants are ChromeOS's include/ec_commands.h, as
// carried in coreboot's src/ec/google/chromeec/ec_commands.h.
package crosfp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Host command codes.
const (
	cmdGetCmdVersions  = 0x0008
	cmdGetProtocolInfo = 0x000B
	cmdFPMode          = 0x0402
	cmdFPInfo          = 0x0403
	cmdFPFrame         = 0x0404
	cmdFPTemplate      = 0x0405
	cmdFPContext       = 0x0406
	cmdFPSeed          = 0x0408
	cmdFPEncStatus     = 0x0409
)

// FP_MODE bits.
const (
	ModeDeepSleep     uint32 = 1 << 0
	ModeFingerDown    uint32 = 1 << 1
	ModeFingerUp      uint32 = 1 << 2
	ModeCapture       uint32 = 1 << 3
	ModeEnrollSession uint32 = 1 << 4
	ModeEnrollImage   uint32 = 1 << 5
	ModeMatch         uint32 = 1 << 6
	ModeResetSensor   uint32 = 1 << 7
	modeDontChange    uint32 = 1 << 31
)

// TemplateFormat is the encrypted template format this package knows. The
// seed command carries it too, so a mismatch is refused there.
const TemplateFormat = 4

// SeedSize and UserIDSize are the seed's and the context's lengths.
const (
	SeedSize   = 32
	UserIDSize = 32
)

const (
	frameIndexShift    = 28
	frameIndexTemplate = 1
	templateCommit     = 0x80000000
	encStatusSeedSet   = 1 << 0
	contextAsync       = 0
	contextGetResult   = 1
	// The EC's packet header and a command's request or response header,
	// which the protocol's packet sizes include.
	packetOverhead = 8
	// Used when the MCU does not report its packet sizes.
	defaultPayload = 256
)

// Result is an EC result code other than success.
type Result uint32

// Results the package tells apart.
const (
	ResultInvalidCommand Result = 1
	ResultError          Result = 2
	ResultInvalidParam   Result = 3
	ResultAccessDenied   Result = 4
	ResultInvalidVersion Result = 6
	ResultUnavailable    Result = 9
	ResultTimeout        Result = 10
	ResultBusy           Result = 16
)

func (r Result) Error() string {
	names := map[Result]string{
		ResultInvalidCommand: "invalid command", ResultError: "error",
		ResultInvalidParam: "invalid parameter", ResultAccessDenied: "access denied",
		ResultInvalidVersion: "invalid version", ResultUnavailable: "unavailable",
		ResultTimeout: "timeout", ResultBusy: "busy",
	}
	if n, ok := names[r]; ok {
		return "fpmcu: " + n
	}
	return fmt.Sprintf("fpmcu: result %d", uint32(r))
}

// Transport carries host commands to the MCU and its events back. The real
// one is the cros_ec character device (Open); tests supply fakes.
type Transport interface {
	// Command sends cmd at version with out as its parameters and returns
	// up to insize bytes of response. An EC result other than success is
	// returned as a Result.
	Command(cmd, version uint32, out []byte, insize int) ([]byte, error)
	// NextEvent waits for the next fingerprint event.
	NextEvent(ctx context.Context) (Event, error)
	Close() error
}

// Event is one fingerprint event: the MCU's fp_events word.
type Event uint32

// Event bits.
const (
	EventEnroll     Event = 1 << 27
	EventMatch      Event = 1 << 28
	EventFingerDown Event = 1 << 29
	EventFingerUp   Event = 1 << 30
	EventImageReady Event = 1 << 31
)

// Code is the event's error code (EC_MKBP_FP_ERRCODE).
func (e Event) Code() uint32 { return uint32(e) & 0xF }

// Progress is an enroll event's percent complete.
func (e Event) Progress() int { return int((uint32(e) & 0x00000FF0) >> 4) }

// MatchIndex is a match event's template index.
func (e Event) MatchIndex() int { return int((uint32(e) & 0x0000F000) >> 12) }

// Enroll event codes.
const (
	EnrollOK          = 0
	EnrollLowQuality  = 1
	EnrollImmobile    = 2
	EnrollLowCoverage = 3
	EnrollInternal    = 5
)

// Match event codes.
const (
	MatchNo            = 0
	MatchYes           = 1
	MatchNoLowQuality  = 2
	MatchYesUpdated    = 3
	MatchNoLowCoverage = 4
	MatchYesUpdateFail = 5
	MatchNoInternal    = 6
	MatchNoTemplates   = 7
	MatchNoAuthFail    = 8
)

// Info is what FP_INFO reports.
type Info struct {
	VendorID, ProductID, ModelID, Version uint32
	Errors                                uint16
	TemplateSize                          uint32
	TemplateMax, TemplateValid            uint16
	TemplateDirty                         uint32
	TemplateVersion                       uint32
}

// MCU is a fingerprint MCU behind a Transport.
type MCU struct {
	t              Transport
	maxIn, maxOut  int
	pollEvery      time.Duration
	contextTimeout time.Duration
}

// New wraps t, asking the MCU for its packet sizes.
func New(t Transport) *MCU {
	m := &MCU{t: t, maxIn: defaultPayload, maxOut: defaultPayload,
		pollEvery: 50 * time.Millisecond, contextTimeout: 5 * time.Second}
	if r, err := t.Command(cmdGetProtocolInfo, 0, nil, 12); err == nil && len(r) >= 8 {
		req := int(binary.LittleEndian.Uint16(r[4:6]))
		resp := int(binary.LittleEndian.Uint16(r[6:8]))
		if req > packetOverhead*2 {
			m.maxOut = req - packetOverhead
		}
		if resp > packetOverhead*2 {
			m.maxIn = resp - packetOverhead
		}
	}
	return m
}

// Transport returns the transport the MCU runs over.
func (m *MCU) Transport() Transport { return m.t }

// CommandVersions reports which versions of cmd the MCU supports, as a
// bit mask.
func (m *MCU) CommandVersions(cmd uint16) (uint32, error) {
	out := make([]byte, 2)
	binary.LittleEndian.PutUint16(out, cmd)
	r, err := m.t.Command(cmdGetCmdVersions, 1, out, 4)
	if err != nil {
		return 0, err
	}
	if len(r) < 4 {
		return 0, errShort
	}
	return binary.LittleEndian.Uint32(r), nil
}

var errShort = errors.New("fpmcu: short response")

// Info reads FP_INFO (version 2: the sensor, the templates, and the
// capture types, which are not kept).
func (m *MCU) Info() (Info, error) {
	r, err := m.t.Command(cmdFPInfo, 2, nil, m.maxIn)
	if err != nil {
		return Info{}, err
	}
	if len(r) < 36 {
		return Info{}, errShort
	}
	le := binary.LittleEndian
	return Info{
		VendorID: le.Uint32(r[0:]), ProductID: le.Uint32(r[4:]),
		ModelID: le.Uint32(r[8:]), Version: le.Uint32(r[12:]),
		Errors:       le.Uint16(r[18:]),
		TemplateSize: le.Uint32(r[20:]), TemplateMax: le.Uint16(r[24:]),
		TemplateValid: le.Uint16(r[26:]), TemplateDirty: le.Uint32(r[28:]),
		TemplateVersion: le.Uint32(r[32:]),
	}, nil
}

// SeedSet reports whether a seed has been set since the MCU last booted.
func (m *MCU) SeedSet() (bool, error) {
	r, err := m.t.Command(cmdFPEncStatus, 0, nil, 8)
	if err != nil {
		return false, err
	}
	if len(r) < 8 {
		return false, errShort
	}
	return binary.LittleEndian.Uint32(r[4:])&encStatusSeedSet != 0, nil
}

// SetSeed sets the seed the MCU derives its template keys from. The MCU
// takes one seed per boot and refuses another.
func (m *MCU) SetSeed(seed [SeedSize]byte) error {
	out := make([]byte, 4+SeedSize)
	binary.LittleEndian.PutUint16(out, TemplateFormat)
	copy(out[4:], seed[:])
	_, err := m.t.Command(cmdFPSeed, 0, out, 0)
	return err
}

// SetContext sets the user context, which also clears every template the
// MCU holds. Version 1 is asynchronous: start it, then poll for the
// result while the MCU reports busy.
func (m *MCU) SetContext(ctx context.Context, user [UserIDSize]byte) error {
	out := make([]byte, 4+UserIDSize)
	out[0] = contextAsync
	copy(out[4:], user[:])
	if _, err := m.t.Command(cmdFPContext, 1, out, 0); err != nil {
		return err
	}
	out[0] = contextGetResult
	deadline := time.Now().Add(m.contextTimeout)
	for {
		_, err := m.t.Command(cmdFPContext, 1, out, 0)
		if !errors.Is(err, ResultBusy) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("fpmcu: setting the context: %w", ResultTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.pollEvery):
		}
	}
}

// SetMode sets the MCU's mode and returns the mode it is in afterwards.
func (m *MCU) SetMode(mode uint32) (uint32, error) {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, mode)
	r, err := m.t.Command(cmdFPMode, 0, out, 4)
	if err != nil {
		return 0, err
	}
	if len(r) < 4 {
		return 0, errShort
	}
	return binary.LittleEndian.Uint32(r), nil
}

// Mode reports the MCU's mode without changing it.
func (m *MCU) Mode() (uint32, error) { return m.SetMode(modeDontChange) }

// ReadTemplate reads template idx, encrypted, size bytes long (the
// TemplateSize FP_INFO reports).
func (m *MCU) ReadTemplate(idx int, size int) ([]byte, error) {
	if idx < 0 || idx >= 1<<4-1 {
		return nil, fmt.Errorf("fpmcu: template index %d out of range", idx)
	}
	buf := make([]byte, 0, size)
	out := make([]byte, 8)
	for len(buf) < size {
		n := size - len(buf)
		if n > m.maxIn {
			n = m.maxIn
		}
		off := uint32(idx+frameIndexTemplate)<<frameIndexShift | uint32(len(buf))
		binary.LittleEndian.PutUint32(out[0:], off)
		binary.LittleEndian.PutUint32(out[4:], uint32(n))
		r, err := m.t.Command(cmdFPFrame, 0, out, n)
		if err != nil {
			return nil, fmt.Errorf("fpmcu: reading template %d at %d: %w", idx, len(buf), err)
		}
		if len(r) < n {
			return nil, errShort
		}
		buf = append(buf, r[:n]...)
	}
	return buf, nil
}

// UploadTemplate loads one encrypted template into the MCU's next slot.
func (m *MCU) UploadTemplate(blob []byte) error {
	chunk := m.maxOut - 8
	if chunk <= 0 {
		return errors.New("fpmcu: no room for template data")
	}
	for off := 0; off < len(blob); off += chunk {
		n := len(blob) - off
		if n > chunk {
			n = chunk
		}
		size := uint32(n)
		if off+n == len(blob) {
			size |= templateCommit
		}
		out := make([]byte, 8+n)
		binary.LittleEndian.PutUint32(out[0:], uint32(off))
		binary.LittleEndian.PutUint32(out[4:], size)
		copy(out[8:], blob[off:off+n])
		if _, err := m.t.Command(cmdFPTemplate, 0, out, 0); err != nil {
			return fmt.Errorf("fpmcu: loading template at %d: %w", off, err)
		}
	}
	return nil
}

// Wait waits for the next event with any of the bits in want set, and
// discards the rest.
func (m *MCU) Wait(ctx context.Context, want Event) (Event, error) {
	for {
		e, err := m.t.NextEvent(ctx)
		if err != nil {
			return 0, err
		}
		if e&want != 0 {
			return e, nil
		}
	}
}
