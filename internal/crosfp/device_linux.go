package crosfp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// DefaultPath is the fingerprint MCU's character device.
const DefaultPath = "/dev/cros_fp"

// The cros_ec character device's ioctls, from <linux/cros_ec_chardev.h>:
// CROS_EC_DEV_IOCXCMD_V2 is _IOWR(0xEC, 0, struct cros_ec_command_v2),
// whose fixed part is five u32 (version, command, outsize, insize,
// result), and CROS_EC_DEV_IOCEVENTMASK_V2 is _IO(0xEC, 2).
const (
	ioctlXCmd      = 0xC014EC00
	ioctlEventMask = 0x0000EC02
	cmdHeader      = 20
	// EC_MKBP_EVENT_FINGERPRINT.
	mkbpFingerprint = 5
	// How often a blocked event read looks at its context.
	readSlice = 250 * time.Millisecond
)

// Device is the MCU's character device.
type Device struct {
	f *os.File
}

// Open opens the character device at path and asks it for fingerprint
// events.
func Open(path string) (*Device, error) {
	// Non-blocking, so the runtime poller serves reads and deadlines work.
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	d := &Device{f: f}
	if err := d.ioctl(ioctlEventMask, uintptr(1<<mkbpFingerprint)); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: event mask: %w", path, err)
	}
	return d, nil
}

func (d *Device) ioctl(req, arg uintptr) error {
	rc, err := d.f.SyscallConn()
	if err != nil {
		return err
	}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
	}); err != nil {
		return err
	}
	if errno != 0 {
		return errno
	}
	return nil
}

// Command implements Transport.
func (d *Device) Command(cmd, version uint32, out []byte, insize int) ([]byte, error) {
	if insize < 0 {
		return nil, errors.New("fpmcu: negative response size")
	}
	n := len(out)
	if insize > n {
		n = insize
	}
	buf := make([]byte, cmdHeader+n)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], version)
	le.PutUint32(buf[4:], cmd)
	le.PutUint32(buf[8:], uint32(len(out)))
	le.PutUint32(buf[12:], uint32(insize))
	copy(buf[cmdHeader:], out)
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var got uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		got, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlXCmd, uintptr(unsafe.Pointer(&buf[0])))
	}); err != nil {
		return nil, err
	}
	// The kernel returns the EC's result in the header and fails the
	// ioctl with EPROTO when it is not success.
	if res := Result(le.Uint32(buf[16:])); res != 0 {
		return nil, res
	}
	if errno != 0 {
		return nil, fmt.Errorf("fpmcu: command 0x%04x: %w", cmd, errno)
	}
	if int(got) > insize {
		got = uintptr(insize)
	}
	return buf[cmdHeader : cmdHeader+int(got)], nil
}

// NextEvent implements Transport. A read returns the event type and its
// data; only fingerprint events are asked for, but others are skipped.
func (d *Device) NextEvent(ctx context.Context) (Event, error) {
	buf := make([]byte, 64)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := d.f.SetReadDeadline(time.Now().Add(readSlice)); err != nil {
			return 0, err
		}
		n, err := d.f.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n >= 5 && buf[0] == mkbpFingerprint {
			return Event(binary.LittleEndian.Uint32(buf[1:5])), nil
		}
	}
}

// Close implements Transport.
func (d *Device) Close() error { return d.f.Close() }
