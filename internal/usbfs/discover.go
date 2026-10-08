// Package usbfs drives a USB device through the kernel's usbdevfs interface
// (/dev/bus/usb) without libusb or cgo, and finds devices through sysfs.
package usbfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNotFound is returned when no device matches the requested IDs.
var ErrNotFound = errors.New("usb device not found")

// Info describes one device as sysfs reports it at the moment of the scan.
// Bus and Addr change when the device re-enumerates (for instance after
// resume), so an Info must not be cached across a disconnect.
type Info struct {
	SysPath string // e.g. /sys/bus/usb/devices/1-9
	Bus     int
	Addr    int
	Vendor  uint16
	Product uint16
	// Config is bConfigurationValue; 0 means the device is unconfigured.
	Config int
}

// Bus locates devices. The roots are fields so tests can point them at a
// fake tree; the zero value is not usable, use System.
type Bus struct {
	SysRoot string // directory holding the sysfs device entries
	DevRoot string // directory holding BBB/DDD device nodes
}

// System is the live machine's layout.
var System = Bus{SysRoot: "/sys/bus/usb/devices", DevRoot: "/dev/bus/usb"}

// Find returns the first device with the given vendor and product IDs.
func (b Bus) Find(vendor, product uint16) (Info, error) {
	entries, err := os.ReadDir(b.SysRoot)
	if err != nil {
		return Info{}, fmt.Errorf("scan %s: %w", b.SysRoot, err)
	}
	for _, e := range entries {
		// Interface entries ("1-9:1.0") and root hubs' interfaces carry a
		// colon; only whole devices have the descriptor files read here.
		if strings.Contains(e.Name(), ":") {
			continue
		}
		info, err := readInfo(filepath.Join(b.SysRoot, e.Name()))
		if err != nil {
			continue
		}
		if info.Vendor == vendor && info.Product == product {
			return info, nil
		}
	}
	return Info{}, fmt.Errorf("%04x:%04x: %w", vendor, product, ErrNotFound)
}

// NodePath is the usbdevfs character device for info.
func (b Bus) NodePath(info Info) string {
	return filepath.Join(b.DevRoot, fmt.Sprintf("%03d", info.Bus), fmt.Sprintf("%03d", info.Addr))
}

func readInfo(dir string) (Info, error) {
	info := Info{SysPath: dir}
	vendor, err := readHex16(dir, "idVendor")
	if err != nil {
		return info, err
	}
	product, err := readHex16(dir, "idProduct")
	if err != nil {
		return info, err
	}
	info.Vendor, info.Product = vendor, product
	if info.Bus, err = readInt(dir, "busnum"); err != nil {
		return info, err
	}
	if info.Addr, err = readInt(dir, "devnum"); err != nil {
		return info, err
	}
	// An unconfigured device reports an empty bConfigurationValue.
	s, err := readAttr(dir, "bConfigurationValue")
	if err != nil {
		return info, err
	}
	if s != "" {
		if info.Config, err = strconv.Atoi(s); err != nil {
			return info, fmt.Errorf("%s/bConfigurationValue: %w", dir, err)
		}
	}
	return info, nil
}

func readAttr(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readHex16(dir, name string) (uint16, error) {
	s, err := readAttr(dir, name)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, fmt.Errorf("%s/%s: %w", dir, name, err)
	}
	return uint16(v), nil
}

func readInt(dir, name string) (int, error) {
	s, err := readAttr(dir, name)
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%s/%s: %w", dir, name, err)
	}
	return v, nil
}
