package usbfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeDev(t *testing.T, root, name string, attrs map[string]string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range attrs {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sensorAttrs(config string) map[string]string {
	return map[string]string{
		"idVendor": "06cb", "idProduct": "009a",
		"busnum": "1", "devnum": "4", "bConfigurationValue": config,
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, root string)
		want    Info
		wantErr error
	}{
		{
			name: "configured sensor among other devices",
			setup: func(t *testing.T, root string) {
				writeDev(t, root, "usb1", map[string]string{
					"idVendor": "1d6b", "idProduct": "0002",
					"busnum": "1", "devnum": "1", "bConfigurationValue": "1",
				})
				// An interface entry must be skipped even if it looked valid.
				writeDev(t, root, "1-9:1.0", sensorAttrs("1"))
				writeDev(t, root, "1-9", sensorAttrs("1"))
			},
			want: Info{Bus: 1, Addr: 4, Vendor: 0x06cb, Product: 0x009a, Config: 1},
		},
		{
			name: "unconfigured device reports config 0",
			setup: func(t *testing.T, root string) {
				writeDev(t, root, "1-9", sensorAttrs(""))
			},
			want: Info{Bus: 1, Addr: 4, Vendor: 0x06cb, Product: 0x009a, Config: 0},
		},
		{
			name: "entries with missing or bad attributes are skipped",
			setup: func(t *testing.T, root string) {
				writeDev(t, root, "1-1", map[string]string{"idVendor": "06cb"})
				bad := sensorAttrs("1")
				bad["busnum"] = "x"
				writeDev(t, root, "1-2", bad)
			},
			wantErr: ErrNotFound,
		},
		{
			name:    "empty bus",
			setup:   func(*testing.T, string) {},
			wantErr: ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setup(t, root)
			got, err := Bus{SysRoot: root, DevRoot: "/dev/bus/usb"}.Find(0x06cb, 0x009a)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.want.SysPath = filepath.Join(root, "1-9")
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFindMissingRoot(t *testing.T) {
	_, err := Bus{SysRoot: filepath.Join(t.TempDir(), "nope")}.Find(1, 2)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want a scan error", err)
	}
}

func TestReadInfoErrors(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]string
	}{
		{"bad vendor", map[string]string{"idVendor": "zz"}},
		{"missing product", map[string]string{"idVendor": "06cb"}},
		{"bad product", map[string]string{"idVendor": "06cb", "idProduct": "zz"}},
		{"missing busnum", map[string]string{"idVendor": "06cb", "idProduct": "009a"}},
		{"missing devnum", map[string]string{"idVendor": "06cb", "idProduct": "009a", "busnum": "1"}},
		{"missing config", map[string]string{"idVendor": "06cb", "idProduct": "009a", "busnum": "1", "devnum": "4"}},
		{"bad config", map[string]string{"idVendor": "06cb", "idProduct": "009a", "busnum": "1", "devnum": "4", "bConfigurationValue": "x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeDev(t, root, "d", tt.attrs)
			if _, err := readInfo(filepath.Join(root, "d")); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestNodePath(t *testing.T) {
	got := System.NodePath(Info{Bus: 1, Addr: 4})
	if got != "/dev/bus/usb/001/004" {
		t.Fatalf("got %s", got)
	}
}

// The request numbers are checked against the values the C headers
// produce on x86-64, so a layout mistake in bulkTransfer shows up here
// rather than as EINVAL against hardware.
func TestIoctlNumbers(t *testing.T) {
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"USBDEVFS_BULK", ioctlBulk, 0xc0185502},
		{"USBDEVFS_SETCONFIGURATION", ioctlSetConfiguration, 0x80045505},
		{"USBDEVFS_CLAIMINTERFACE", ioctlClaimInterface, 0x8004550f},
		{"USBDEVFS_RELEASEINTERFACE", ioctlReleaseInterface, 0x80045510},
		{"USBDEVFS_RESET", ioctlReset, 0x5514},
		{"USBDEVFS_CLEAR_HALT", ioctlClearHalt, 0x80045515},
		{"USBDEVFS_FORBID_SUSPEND", ioctlForbidSuspend, 0x5521},
		{"USBDEVFS_ALLOW_SUSPEND", ioctlAllowSuspend, 0x5522},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %#x, want %#x", tt.name, tt.got, tt.want)
		}
	}
}

func TestMapErrno(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		want  error
	}{
		{syscall.ETIMEDOUT, ErrTimeout},
		{syscall.ENODEV, ErrDisconnected},
		{syscall.ESHUTDOWN, ErrDisconnected},
		{syscall.EPIPE, syscall.EPIPE},
	}
	for _, tt := range tests {
		err := mapErrno(tt.errno)
		if !errors.Is(err, tt.want) || !errors.Is(err, tt.errno) {
			t.Errorf("mapErrno(%v) = %v, want wrapping %v", tt.errno, err, tt.want)
		}
	}
}

func TestOpenMissingNode(t *testing.T) {
	b := Bus{DevRoot: t.TempDir()}
	if _, err := Open(b, Info{Bus: 1, Addr: 4, Config: 1}, 0); err == nil {
		t.Fatal("expected an error")
	}
}

// A regular file stands in for the device node: every ioctl on it fails
// with ENOTTY, which drives the error paths without hardware.
func fakeNode(t *testing.T) (Bus, Info) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "001"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "001", "004"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return Bus{DevRoot: root}, Info{Bus: 1, Addr: 4}
}

func TestOpenIoctlFailures(t *testing.T) {
	b, info := fakeNode(t)
	for _, config := range []int{0, 1} {
		info.Config = config
		_, err := Open(b, info, 0)
		if !errors.Is(err, syscall.ENOTTY) {
			t.Errorf("config %d: err = %v, want ENOTTY", config, err)
		}
	}
}

func TestDeviceOpsOnNonDevice(t *testing.T) {
	b, info := fakeNode(t)
	f, err := os.OpenFile(b.NodePath(info), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{f: f}
	if _, err := d.Bulk(0x81, make([]byte, 8), 0); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("Bulk: %v", err)
	}
	if _, err := d.Bulk(0x01, nil, 0); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("Bulk empty: %v", err)
	}
	if err := d.ClearHalt(0x81); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("ClearHalt: %v", err)
	}
	if err := d.Reset(); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("Reset: %v", err)
	}
	if err := d.AllowSuspend(); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("AllowSuspend: %v", err)
	}
	if err := d.ForbidSuspend(); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("ForbidSuspend: %v", err)
	}
	if err := d.Close(); !errors.Is(err, syscall.ENOTTY) {
		t.Errorf("Close: %v", err)
	}
	if err := d.Close(); err == nil {
		t.Error("second Close: expected an error")
	}
}
