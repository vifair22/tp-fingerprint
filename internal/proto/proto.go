// Package proto is the protocol fpd speaks on its unix socket. pam_fpd.so
// uses the VERIFY exchange only, through pam/fpd_proto.h, which a test
// keeps in step with the constants here; fpctl uses the rest.
//
// A frame is a little-endian u16 type, a u16 payload length and the
// payload. A client sends one request frame and reads event frames until
// a RESULT, after which fpd closes the connection.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// DefaultSocket is where fpd listens.
const DefaultSocket = "/run/fpd/fpd.sock"

// HeaderLen is the size of a frame header.
const HeaderLen = 4

// MaxPayload bounds a frame; anything larger is a protocol error.
const MaxPayload = 4096

// Frame types: requests are below 0x80, events from 0x80.
const (
	ReqVerify   uint16 = 0x0001 // u32 uid, u32 timeout_ms, u32 max_tries
	ReqEnroll   uint16 = 0x0002 // u32 uid, u16 subtype
	ReqList     uint16 = 0x0003 // u32 uid (AllUsers for every user)
	ReqDelete   uint16 = 0x0004 // u32 uid, u16 subtype (0: every finger)
	ReqIdentify uint16 = 0x0005 // u32 timeout_ms

	EvPrompt   uint16 = 0x0081 // empty: touch the sensor now
	EvRetry    uint16 = 0x0082 // u32 reason
	EvResult   uint16 = 0x0083 // u32 result; the last frame
	EvProgress uint16 = 0x0084 // u32 touches accepted (enroll)
	EvFinger   uint16 = 0x0085 // u32 uid, u16 subtype (list, identify)
)

// Fixed payload sizes the PAM module relies on.
const (
	VerifyLen = 12
	PromptLen = 0
	RetryLen  = 4
	ResultLen = 4
)

// AllUsers asks ReqList for every user (root only).
const AllUsers = 0xffffffff

// Retry reasons.
const (
	RetryScan    uint32 = 1
	RetryNoMatch uint32 = 2
)

// Result codes.
const (
	ResultMatch       uint32 = 0 // also plain success for other requests
	ResultNoMatch     uint32 = 1
	ResultNotEnrolled uint32 = 2
	ResultUnavailable uint32 = 3
	ResultBusy        uint32 = 4
	ResultTimeout     uint32 = 5
	ResultDenied      uint32 = 6
	ResultBadRequest  uint32 = 7
	ResultError       uint32 = 8
	ResultCancelled   uint32 = 9
	ResultExists      uint32 = 10
	ResultRemote      uint32 = 11
)

// ResultString describes a result code for logs and fpctl.
func ResultString(r uint32) string {
	names := []string{"match", "no match", "nothing enrolled", "sensor unavailable",
		"sensor busy", "timed out", "permission denied", "bad request", "error",
		"cancelled", "already enrolled", "remote session"}
	if int(r) < len(names) {
		return names[r]
	}
	return fmt.Sprintf("result %d", r)
}

// Frame is one decoded frame.
type Frame struct {
	Type    uint16
	Payload []byte
}

// ErrFrame is a malformed frame.
var ErrFrame = errors.New("malformed frame")

// Write sends one frame.
func Write(w io.Writer, typ uint16, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("%w: %d-byte payload", ErrFrame, len(payload))
	}
	b := make([]byte, HeaderLen, HeaderLen+len(payload))
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(payload)))
	_, err := w.Write(append(b, payload...))
	return err
}

// Read reads one frame.
func Read(r io.Reader) (Frame, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[2:]))
	if n > MaxPayload {
		return Frame{}, fmt.Errorf("%w: %d-byte payload", ErrFrame, n)
	}
	f := Frame{Type: binary.LittleEndian.Uint16(hdr[:]), Payload: make([]byte, n)}
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrFrame, err)
	}
	return f, nil
}

// U32s encodes u32 fields; U16 appends a u16.
func U32s(vs ...uint32) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

// U16 appends v to b.
func U16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }

// Fields decodes a payload of exactly the given field sizes (4 or 2).
func (f Frame) Fields(sizes ...int) ([]uint32, error) {
	want := 0
	for _, s := range sizes {
		want += s
	}
	if len(f.Payload) != want {
		return nil, fmt.Errorf("%w: type 0x%04x with %d bytes, want %d", ErrFrame, f.Type, len(f.Payload), want)
	}
	out := make([]uint32, len(sizes))
	off := 0
	for i, s := range sizes {
		switch s {
		case 4:
			out[i] = binary.LittleEndian.Uint32(f.Payload[off:])
		case 2:
			out[i] = uint32(binary.LittleEndian.Uint16(f.Payload[off:]))
		default:
			return nil, fmt.Errorf("field size %d", s)
		}
		off += s
	}
	return out, nil
}
