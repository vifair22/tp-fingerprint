// Package validity speaks the Synaptics "Metallica" (06cb:009a) sensor
// protocol. It is ported from python-validity
// (https://github.com/uunicorn/python-validity), which is:
//
//	Copyright (c) 2020 uunicorn
//
// under the MIT License, whose full text is in
// LICENSES/python-validity-MIT.txt. The port is distributed under GPL-3.0
// (LICENSE).
package validity

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// USB IDs of the only sensor this package supports.
const (
	VendorID  = 0x06cb
	ProductID = 0x009a
)

// Endpoints. Commands go out on epCmdOut and their replies come back on
// epCmdIn; epData and epInterrupt carry image data and finger events,
// which later stages use.
const (
	epCmdOut uint8 = 0x01
	epCmdIn  uint8 = 0x81
)

// The reference's timeout and reply buffer for a command exchange.
const (
	cmdTimeout = 15 * time.Second
	maxReply   = 100 * 1024
)

// Busy retry, from the fix for python-validity #272: right after the
// device is opened the sensor answers early commands with StatusBusy
// until it has finished starting up.
const (
	busyAttempts = 20
	busyDelay    = 500 * time.Millisecond
)

// Transport is a USB handle able to run bulk transfers; usbfs.Device
// satisfies it.
type Transport interface {
	Bulk(ep uint8, buf []byte, timeout time.Duration) (int, error)
}

// Status is the little-endian 16-bit word every reply starts with.
type Status uint16

// Known status values.
const (
	StatusOK Status = 0x0000
	// StatusBusy is transient: the sensor is still starting up.
	StatusBusy Status = 0x0104
	// StatusSignature means a signed blob failed validation.
	StatusSignature Status = 0x044f
	// StatusNoPartition is what a firmware query returned on a sensor
	// whose flash had no partition table. The name is inferred from that
	// one observation; the reference does not name it.
	StatusNoPartition Status = 0x04af
	// StatusNoFirmware is the reply to a firmware query for a partition
	// with no firmware loaded. It is normal before the first upload.
	StatusNoFirmware Status = 0x04b0
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusBusy:
		return "busy"
	case StatusSignature:
		return "signature validation failed"
	case StatusNoPartition:
		return "no partition"
	case StatusNoFirmware:
		return "no firmware"
	}
	return fmt.Sprintf("0x%04x", uint16(s))
}

// StatusError is a reply carrying a non-zero status.
type StatusError struct {
	Cmd    byte
	Status Status
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("command 0x%02x: sensor status %s", e.Cmd, e.Status)
}

// ErrShortReply is returned for a reply too short to hold what it should.
var ErrShortReply = errors.New("short reply from sensor")

// Link runs plaintext command exchanges. The TLS session, when it exists,
// is layered on top of it.
type Link struct {
	t     Transport
	buf   []byte
	log   *slog.Logger
	sleep func(time.Duration)
}

// NewLink returns a Link over t. Exchanges are logged in hex at debug
// level on log; pass nil to discard them.
func NewLink(t Transport, log *slog.Logger) *Link {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Link{t: t, buf: make([]byte, maxReply), log: log, sleep: time.Sleep}
}

// Raw sends req and returns the whole reply, status word included.
func (l *Link) Raw(req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, errors.New("empty command")
	}
	l.log.Debug("cmd >", "data", hex.EncodeToString(req))
	n, err := l.t.Bulk(epCmdOut, req, cmdTimeout)
	if err != nil {
		return nil, fmt.Errorf("send command 0x%02x: %w", req[0], err)
	}
	if n != len(req) {
		return nil, fmt.Errorf("send command 0x%02x: wrote %d of %d bytes", req[0], n, len(req))
	}
	n, err = l.t.Bulk(epCmdIn, l.buf, cmdTimeout)
	if err != nil {
		return nil, fmt.Errorf("read reply to 0x%02x: %w", req[0], err)
	}
	rsp := append([]byte(nil), l.buf[:n]...)
	l.log.Debug("cmd <", "data", hex.EncodeToString(rsp))
	return rsp, nil
}

// Cmd sends req, retrying while the sensor reports StatusBusy, and splits
// the reply into its status and payload. A non-zero status is returned as
// the Status with the payload and a nil error: whether it is a failure is
// the caller's call (StatusNoFirmware, for one, is normal).
func (l *Link) Cmd(req []byte) (Status, []byte, error) {
	for attempt := 1; ; attempt++ {
		rsp, err := l.Raw(req)
		if err != nil {
			return 0, nil, err
		}
		if len(rsp) < 2 {
			return 0, nil, fmt.Errorf("command 0x%02x: %d-byte reply: %w", req[0], len(rsp), ErrShortReply)
		}
		st := Status(binary.LittleEndian.Uint16(rsp))
		if st != StatusBusy || attempt == busyAttempts {
			return st, rsp[2:], nil
		}
		l.log.Debug("sensor busy, retrying", "cmd", fmt.Sprintf("0x%02x", req[0]), "attempt", attempt)
		l.sleep(busyDelay)
	}
}

// CmdOK is Cmd for commands whose only acceptable status is StatusOK.
func (l *Link) CmdOK(req []byte) ([]byte, error) {
	st, payload, err := l.Cmd(req)
	if err != nil {
		return nil, err
	}
	if st != StatusOK {
		return nil, &StatusError{Cmd: req[0], Status: st}
	}
	return payload, nil
}
