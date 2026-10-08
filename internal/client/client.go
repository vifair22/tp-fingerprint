// Package client talks to fpd over its socket, for fpctl. (pam_fpd.so has
// its own C client for the one exchange it needs.)
package client

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
)

// ErrNoDaemon means nothing is listening on the socket: fpd is not
// running, and fpctl may use the sensor directly.
var ErrNoDaemon = errors.New("fpd is not running")

// ResultError is a request fpd answered with something other than success.
type ResultError struct{ Code uint32 }

func (e *ResultError) Error() string { return proto.ResultString(e.Code) }

// Events receives what fpd reports while a request runs. Nil fields are
// skipped.
type Events struct {
	Prompt   func()
	Retry    func(reason uint32)
	Progress func(touches uint32)
	Finger   func(uid uint32, subtype uint16)
}

// Do sends one request to the fpd at socket and relays its events until
// the result. It returns nil for success, *ResultError for any other
// result, and ErrNoDaemon if fpd is not there.
func Do(socket string, typ uint16, payload []byte, ev Events) error {
	c, err := net.Dial("unix", socket)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return ErrNoDaemon
		}
		return err
	}
	defer c.Close()
	if err := proto.Write(c, typ, payload); err != nil {
		return err
	}
	for {
		f, err := proto.Read(c)
		if err != nil {
			return fmt.Errorf("reading from fpd: %w", err)
		}
		switch f.Type {
		case proto.EvResult:
			v, err := f.Fields(4)
			if err != nil {
				return err
			}
			if v[0] != proto.ResultMatch {
				return &ResultError{v[0]}
			}
			return nil
		case proto.EvPrompt:
			if ev.Prompt != nil {
				ev.Prompt()
			}
		case proto.EvRetry, proto.EvProgress:
			v, err := f.Fields(4)
			if err != nil {
				return err
			}
			if f.Type == proto.EvRetry && ev.Retry != nil {
				ev.Retry(v[0])
			} else if f.Type == proto.EvProgress && ev.Progress != nil {
				ev.Progress(v[0])
			}
		case proto.EvFinger:
			v, err := f.Fields(4, 2)
			if err != nil {
				return err
			}
			if ev.Finger != nil {
				ev.Finger(v[0], uint16(v[1]))
			}
		default:
			return fmt.Errorf("%w: unexpected type 0x%04x", proto.ErrFrame, f.Type)
		}
	}
}
