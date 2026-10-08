package usbfs

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	// ErrTimeout is returned when a transfer did not complete in time.
	ErrTimeout = errors.New("usb transfer timed out")
	// ErrDisconnected is returned once the device has gone away. The handle
	// is dead: find the device again and open a new one (it re-enumerates
	// with a new address after resume).
	ErrDisconnected = errors.New("usb device disconnected")
)

// bulkTransfer mirrors struct usbdevfs_bulktransfer from
// <linux/usbdevice_fs.h>. Go lays it out the same way C does on every
// Linux ABI, including the padding before the pointer on 64-bit targets.
type bulkTransfer struct {
	ep      uint32
	len     uint32
	timeout uint32 // milliseconds; 0 waits forever
	data    unsafe.Pointer
}

// The _IOC encoding from <asm-generic/ioctl.h>.
const (
	iocNone  = 0
	iocWrite = 1
	iocRead  = 2
)

func ioc(dir, nr, size uintptr) uintptr {
	return dir<<30 | size<<16 | uintptr('U')<<8 | nr
}

var (
	ioctlBulk             = ioc(iocRead|iocWrite, 2, unsafe.Sizeof(bulkTransfer{}))
	ioctlSetConfiguration = ioc(iocRead, 5, 4)
	ioctlClaimInterface   = ioc(iocRead, 15, 4)
	ioctlReleaseInterface = ioc(iocRead, 16, 4)
	ioctlReset            = ioc(iocNone, 20, 0)
	ioctlClearHalt        = ioc(iocRead, 21, 4)
	ioctlForbidSuspend    = ioc(iocNone, 33, 0)
	ioctlAllowSuspend     = ioc(iocNone, 34, 0)
)

// Device is an open usbdevfs handle with one claimed interface. It is not
// safe for concurrent use; the sensor protocol is strictly request/response
// and has a single owner.
type Device struct {
	f     *os.File
	iface uint32
}

// Open opens the device node for info, selects configuration 1 if the
// device is unconfigured, and claims iface. Claiming fails with EBUSY if a
// kernel driver is bound to the interface; nothing in mainline binds to
// 06cb:009a, so that is not handled here.
func Open(b Bus, info Info, iface int) (*Device, error) {
	path := b.NodePath(info)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	d := &Device{f: f, iface: uint32(iface)}
	if info.Config == 0 {
		if err := d.ioctlInt(ioctlSetConfiguration, 1); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("set configuration on %s: %w", path, err)
		}
	}
	if err := d.ioctlInt(ioctlClaimInterface, d.iface); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("claim interface %d on %s: %w", iface, path, err)
	}
	return d, nil
}

// Close releases the interface and closes the node. A release failure on a
// device that has already gone is expected and not reported.
func (d *Device) Close() error {
	rerr := d.ioctlInt(ioctlReleaseInterface, d.iface)
	cerr := d.f.Close()
	if cerr != nil {
		return fmt.Errorf("close usb device: %w", cerr)
	}
	if rerr != nil && !errors.Is(rerr, ErrDisconnected) {
		return fmt.Errorf("release interface %d: %w", d.iface, rerr)
	}
	return nil
}

// Bulk runs one bulk or interrupt transfer (usbdevfs handles both through
// the same ioctl). The direction comes from bit 7 of ep. It returns the
// number of bytes moved; an IN transfer ends early on a short packet.
func (d *Device) Bulk(ep uint8, buf []byte, timeout time.Duration) (int, error) {
	bt := bulkTransfer{
		ep:      uint32(ep),
		len:     uint32(len(buf)),
		timeout: uint32(timeout / time.Millisecond),
	}
	if len(buf) > 0 {
		bt.data = unsafe.Pointer(&buf[0])
	}
	// No EINTR retry: the kernel waits for the URB uninterruptibly, and
	// resubmitting an OUT transfer that may have reached the device would
	// send the command twice.
	n, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.f.Fd(), ioctlBulk, uintptr(unsafe.Pointer(&bt)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, fmt.Errorf("bulk ep 0x%02x: %w", ep, mapErrno(errno))
	}
	return int(n), nil
}

// ClearHalt clears a stall on ep.
func (d *Device) ClearHalt(ep uint8) error {
	return d.ioctlInt(ioctlClearHalt, uint32(ep))
}

// Reset issues a USB port reset. The device usually re-enumerates
// afterwards, so the handle should be closed and the device found again.
func (d *Device) Reset() error {
	return d.ioctl(ioctlReset, 0)
}

// AllowSuspend lets the kernel autosuspend the device while this handle
// stays open. By default an open usbfs handle keeps the device, and the
// hub and controller above it, awake for as long as it is held. After
// this call no transfer may be made until ForbidSuspend.
func (d *Device) AllowSuspend() error {
	return d.ioctl(ioctlAllowSuspend, 0)
}

// ForbidSuspend wakes the device if it autosuspended and keeps it awake,
// so transfers can be made again.
func (d *Device) ForbidSuspend() error {
	return d.ioctl(ioctlForbidSuspend, 0)
}

func (d *Device) ioctlInt(req uintptr, v uint32) error {
	err := d.ioctl(req, uintptr(unsafe.Pointer(&v)))
	runtime.KeepAlive(&v)
	return err
}

func (d *Device) ioctl(req, arg uintptr) error {
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.f.Fd(), req, arg)
		switch errno {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		default:
			return mapErrno(errno)
		}
	}
}

func mapErrno(errno syscall.Errno) error {
	switch errno {
	case syscall.ETIMEDOUT:
		return fmt.Errorf("%w: %w", ErrTimeout, errno)
	case syscall.ENODEV, syscall.ESHUTDOWN:
		return fmt.Errorf("%w: %w", ErrDisconnected, errno)
	default:
		return errno
	}
}
