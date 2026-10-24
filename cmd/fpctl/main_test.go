package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"git.airies.net/vifair22/tp-fingerprint/internal/proto"
	"git.airies.net/vifair22/tp-fingerprint/internal/validity"
)

// replaySensor answers each command with the next canned reply, which is
// all fpctl's own logic needs; the protocol is tested in validity.
type replaySensor struct {
	replies  []string
	next     []byte
	closeErr error
	closed   bool
}

func (r *replaySensor) Bulk(ep uint8, buf []byte, _ time.Duration) (int, error) {
	if ep&0x80 == 0 {
		if len(r.replies) == 0 {
			return 0, errors.New("script exhausted")
		}
		r.next, _ = hex.DecodeString(strings.ReplaceAll(r.replies[0], " ", ""))
		r.replies = r.replies[1:]
		return len(buf), nil
	}
	return copy(buf, r.next), nil
}

func (r *replaySensor) Close() error {
	r.closed = true
	return r.closeErr
}

const rom = "0000f0b05e54a40000000607013000010000ad1a4b6869f400"

func runWith(t *testing.T, open func() (sensor, string, error), args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if open == nil {
		open = func() (sensor, string, error) { return nil, "", errors.New("no sensor in this test") }
	}
	code := run(&env{stdout: &out, stderr: &errOut, open: open, socket: noDaemon}, args)
	return code, out.String(), errOut.String()
}

// noDaemon is a socket path nothing listens on: fpd is "not running".
const noDaemon = "/nonexistent/fpd.sock"

func opener(s *replaySensor) func() (sensor, string, error) {
	return func() (sensor, string, error) { return s, "fake", nil }
}

func TestDispatch(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		code      int
		stdout    string
		stderr    string
		notStderr string
	}{
		{name: "no args", code: 1, stderr: "commands:"},
		{name: "top-level help", args: []string{"--help"}, stdout: "commands:"},
		{name: "unknown command", args: []string{"nope"}, code: 1, stderr: `unknown command "nope"`},
		{name: "version", args: []string{"version"}, stdout: "fpctl 0.0.0_unknown.dev"},
		{name: "version rejects args", args: []string{"version", "x"}, code: 1, stderr: "usage: fpctl version"},
		{name: "help overview", args: []string{"help"}, stdout: "probe"},
		{name: "help for a command", args: []string{"help", "probe"}, stdout: "--trace"},
		{name: "help for unknown", args: []string{"help", "nope"}, code: 1, stderr: "usage: fpctl help"},
		{name: "help too many", args: []string{"help", "a", "b"}, code: 1, stderr: "too many"},
		{name: "probe --help", args: []string{"probe", "--help"}, stdout: "usage: fpctl probe"},
		{name: "probe bad flag", args: []string{"probe", "--bogus"}, code: 1, stderr: "usage: fpctl probe"},
		{
			name: "probe open failure prints no usage", args: []string{"probe"}, code: 1,
			stderr: "no sensor in this test", notStderr: "usage:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runWith(t, nil, tt.args...)
			if code != tt.code {
				t.Errorf("exit %d, want %d (stderr %q)", code, tt.code, errOut)
			}
			if !strings.Contains(out, tt.stdout) {
				t.Errorf("stdout %q lacks %q", out, tt.stdout)
			}
			if !strings.Contains(errOut, tt.stderr) {
				t.Errorf("stderr %q lacks %q", errOut, tt.stderr)
			}
			if tt.notStderr != "" && strings.Contains(errOut, tt.notStderr) {
				t.Errorf("stderr %q contains %q", errOut, tt.notStderr)
			}
		})
	}
}

func TestProbeUnpartitioned(t *testing.T) {
	// The replies this T480's sensor gave on 2026-10-07.
	s := &replaySensor{replies: []string{
		"0000c800400000101000000101000000",
		rom,
		"00000200210010010000000000000000000000000c3d721a",
		"af04",
	}}
	code, out, errOut := runWith(t, opener(s), "probe", "--trace")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"sensor   fake",
		"rom      6.7 build 164, product 0x30, timestamp 0x545eb0f0 (2014-11-09T00:10:24Z)",
		"flash    jedec 00c8:0040, 4096 blocks x 256 bytes, unknown 0010 0001, 0 partitions",
		"cmd 0x19 0200 2100 1001",
		"         0000 0c3d 721a",
		"fwext    not loaded (no partition)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "cmd >") {
		t.Errorf("--trace logged nothing: %q", errOut)
	}
	if !s.closed {
		t.Error("sensor not closed")
	}
}

func TestProbeFormattedWithFirmware(t *testing.T) {
	s := &replaySensor{
		replies: []string{
			"0000" + "c800 4000 0010 1000 0001 0100 0100" + "01 02 0300 00100000 00200000",
			rom,
			"0000",
			"0000" + "0100 0100 0100 c28c745a" + "0100 3446 0200 0700 d03e0000",
		},
		closeErr: errors.New("close failed"),
	}
	code, out, errOut := runWith(t, opener(s), "probe")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"1 partitions",
		"partition 0x01  type 0x02  access 0x0003  offset 0x00001000  size 0x00002000",
		"cmd 0x19 (empty)",
		"fwext    1.1 built 2018-02-02T16:07:30Z, 1 modules",
		"module type 0x0001  subtype 0x4634  version 2.7  size 16080",
	} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), strings.Join(strings.Fields(want), " ")) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errOut, "close failed") {
		t.Errorf("close error not logged: %q", errOut)
	}
}

func TestProbeSensorError(t *testing.T) {
	s := &replaySensor{replies: []string{"0100"}}
	code, _, errOut := runWith(t, opener(s), "probe")
	if code != 1 || !strings.Contains(errOut, "command 0x3e: sensor status 0x0001") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !s.closed {
		t.Error("sensor not closed after an error")
	}
}

func TestUnformattedFlashReport(t *testing.T) {
	s := &replaySensor{replies: []string{"0000", rom, "0000", "b004"}}
	_, out, _ := runWith(t, opener(s), "probe")
	for _, want := range []string{"flash    not formatted", "fwext    not loaded (no firmware)"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

const (
	flashUnpartitioned = "0000c800400000101000000101000000"
	flashPartitioned   = "0000c80040000010100000010100" + "0100" + "010407000010000000100000"
)

func TestPairRefusesPartitionedSensor(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "host-secret")
	s := &replaySensor{replies: []string{flashPartitioned}}
	code, _, errOut := runWith(t, opener(s), "pair", "--secret", secret)
	if code != 1 || !strings.Contains(errOut, "already partitioned") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if _, err := os.Stat(secret); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secret created for a sensor that was not paired: %v", err)
	}
}

func TestPairCreatesSecretThenReportsSensorFailure(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "fpd", "host-secret")
	// Pair re-reads the flash info, then send_init's first command fails.
	s := &replaySensor{replies: []string{flashUnpartitioned, flashUnpartitioned, "0100"}}
	code, _, errOut := runWith(t, opener(s), "pair", "--secret", secret)
	if code != 1 || !strings.Contains(errOut, "start-up") || !strings.Contains(errOut, "back it up") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
}

func TestPairErrors(t *testing.T) {
	t.Run("flash info", func(t *testing.T) {
		s := &replaySensor{replies: []string{"0100"}}
		if code, _, _ := runWith(t, opener(s), "pair", "--secret", filepath.Join(t.TempDir(), "s")); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("secret unusable", func(t *testing.T) {
		dir := t.TempDir()
		bad := filepath.Join(dir, "s")
		if err := os.WriteFile(bad, []byte("short"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := &replaySensor{replies: []string{flashUnpartitioned}}
		code, _, errOut := runWith(t, opener(s), "pair", "--secret", bad)
		if code != 1 || !strings.Contains(errOut, "5 bytes") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("bad flag", func(t *testing.T) {
		if code, _, errOut := runWith(t, nil, "pair", "extra"); code != 1 || !strings.Contains(errOut, "usage: fpctl pair") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
}

func TestStatus(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "host-secret")
	t.Run("no secret", func(t *testing.T) {
		code, _, errOut := runWith(t, nil, "status", "--secret", secret)
		if code != 1 || !strings.Contains(errOut, "no such file") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	if err := os.WriteFile(secret, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("unpaired sensor", func(t *testing.T) {
		s := &replaySensor{replies: []string{flashUnpartitioned}}
		code, _, errOut := runWith(t, opener(s), "status", "--secret", secret)
		if code != 1 || !strings.Contains(errOut, "not paired") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("open failure", func(t *testing.T) {
		code, _, errOut := runWith(t, nil, "status", "--secret", secret)
		if code != 1 || !strings.Contains(errOut, "no sensor") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("bad flag", func(t *testing.T) {
		if code, _, _ := runWith(t, nil, "status", "--nope"); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
}

func TestFactoryResetCommand(t *testing.T) {
	t.Run("needs --yes", func(t *testing.T) {
		opened := false
		open := func() (sensor, string, error) { opened = true; return nil, "", errors.New("x") }
		code, _, errOut := runWith(t, open, "factory-reset")
		if code != 1 || !strings.Contains(errOut, "without --yes") || opened {
			t.Fatalf("exit %d, opened %v, stderr %q", code, opened, errOut)
		}
	})
	t.Run("wipes", func(t *testing.T) {
		s := &replaySensor{replies: []string{"0000", "0000", "0000"}}
		code, out, errOut := runWith(t, opener(s), "factory-reset", "--yes")
		if code != 0 || !strings.Contains(out, "reset fake") || !s.closed {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
	t.Run("sensor refuses", func(t *testing.T) {
		s := &replaySensor{replies: []string{"0100"}}
		if code, _, errOut := runWith(t, opener(s), "factory-reset", "--yes"); code != 1 || !strings.Contains(errOut, "reset program") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("bad flag", func(t *testing.T) {
		if code, _, _ := runWith(t, nil, "factory-reset", "--nope"); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
}

// fetchEnv sets up a local installer pinned in the env and an innoextract
// stand-in that writes a firmware file shaped like the real one (or, with
// bad set, one without the header terminator).
func fetchEnv(t *testing.T, bad bool) (installer, inno string, pin string) {
	t.Helper()
	dir := t.TempDir()
	installer = filepath.Join(dir, "nz3gf07w.exe")
	if err := os.WriteFile(installer, []byte("pretend installer"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha512.Sum512([]byte("pretend installer"))
	pin = hex.EncodeToString(h[:])
	header := `printf 'fwext header\x1a'`
	if bad {
		header = `printf 'no terminator'`
	}
	script := `#!/bin/bash
while [ $# -gt 0 ]; do
  case $1 in --output-dir) out=$2; shift ;; --include) inc=$2; shift ;; esac
  shift
done
mkdir -p "$out/app"
{ ` + header + `; head -c 1000 /dev/zero; } > "$out/app/$inc"
`
	inno = filepath.Join(dir, "innoextract")
	if err := os.WriteFile(inno, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return installer, inno, pin
}

// fakeFirmwareSHA256 is the hash of what the innoextract stand-in writes.
func fakeFirmwareSHA256(bad bool) string {
	b := []byte("fwext header\x1a")
	if bad {
		b = []byte("no terminator")
	}
	h := sha256.Sum256(append(b, make([]byte, 1000)...))
	return hex.EncodeToString(h[:])
}

func runFetch(t *testing.T, pin string, args ...string) (int, string, string) {
	return runFetchPinned(t, pin, fakeFirmwareSHA256(false), args...)
}

func runFetchPinned(t *testing.T, pin, fwPin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	e := &env{stdout: &out, stderr: &errOut, installerSHA512: pin, firmwareSHA256: fwPin, socket: noDaemon}
	code := run(e, append([]string{"fetch-firmware"}, args...))
	return code, out.String(), errOut.String()
}

func TestFetchFirmware(t *testing.T) {
	installer, inno, pin := fetchEnv(t, false)
	dst := filepath.Join(t.TempDir(), "fpd", "fw.xpfwext")
	code, out, errOut := runFetch(t, pin, "--installer", installer, "--innoextract", inno, "--out", dst)
	if code != 0 || !strings.Contains(out, "installed "+dst) || !strings.Contains(out, "matches the pin") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if st, err := os.Stat(dst); err != nil || st.Size() != int64(len("fwext header\x1a")+1000) {
		t.Fatalf("installed file: %v, %v", st, err)
	}

	t.Run("pin mismatch", func(t *testing.T) {
		code, _, errOut := runFetch(t, strings.Repeat("0", 128), "--installer", installer, "--innoextract", inno)
		if code != 1 || !strings.Contains(errOut, "pinned SHA-512") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("not a firmware file", func(t *testing.T) {
		installer, inno, pin := fetchEnv(t, true)
		dst := filepath.Join(t.TempDir(), "fw")
		code, _, errOut := runFetchPinned(t, pin, fakeFirmwareSHA256(true), "--installer", installer, "--innoextract", inno, "--out", dst)
		if code != 1 || !strings.Contains(errOut, "no header terminator") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a bad firmware file was installed")
		}
	})
	t.Run("firmware pin mismatch", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "fw")
		code, _, errOut := runFetchPinned(t, pin, strings.Repeat("0", 64), "--installer", installer, "--innoextract", inno, "--out", dst)
		if code != 1 || !strings.Contains(errOut, "pinned SHA-256") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("an unpinned firmware file was installed")
		}
	})
	t.Run("innoextract missing", func(t *testing.T) {
		code, _, errOut := runFetch(t, pin, "--installer", installer, "--innoextract", filepath.Join(t.TempDir(), "x"))
		if code != 1 || !strings.Contains(errOut, "innoextract") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("download fails", func(t *testing.T) {
		var out, errOut bytes.Buffer
		failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("offline")
		})}
		e := &env{stdout: &out, stderr: &errOut, installerSHA512: pin, http: failing, socket: noDaemon}
		if code := run(e, []string{"fetch-firmware"}); code != 1 || !strings.Contains(errOut.String(), "offline") {
			t.Fatalf("exit %d, stderr %q", code, errOut.String())
		}
	})
	t.Run("bad flag", func(t *testing.T) {
		if code, _, _ := runFetch(t, pin, "--nope"); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUploadFirmwareCommand(t *testing.T) {
	dir := t.TempDir()
	fw := filepath.Join(dir, "fw")
	os.WriteFile(fw, append([]byte("hdr\x1a"), make([]byte, 1000)...), 0o600)
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, make([]byte, 32), 0o600)
	tests := []struct {
		name string
		args []string
		s    *replaySensor
		want string
	}{
		{"missing firmware", []string{"--file", filepath.Join(dir, "nope")}, nil, "fetch-firmware first"},
		{"not firmware", []string{"--file", secret}, nil, "no header terminator"},
		{"missing secret", []string{"--file", fw, "--secret", filepath.Join(dir, "nope")}, nil, "host secret"},
		{"unpaired sensor", []string{"--file", fw, "--secret", secret}, &replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
		{"bad flag", []string{"--nope"}, nil, "usage: fpctl upload-firmware"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var open func() (sensor, string, error)
			if tt.s != nil {
				open = opener(tt.s)
			}
			code, _, errOut := runWith(t, open, append([]string{"upload-firmware"}, tt.args...)...)
			if code != 1 || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, errOut, tt.want)
			}
		})
	}
}

func TestCalibrateCommandErrors(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, make([]byte, 32), 0o600)
	tests := []struct {
		name string
		args []string
		s    *replaySensor
		want string
	}{
		{"missing secret", []string{"--secret", filepath.Join(dir, "nope")}, nil, "host secret"},
		{"unreadable calibration", []string{"--secret", secret, "--calib", dir}, nil, "is a directory"},
		{"unpaired sensor", []string{"--secret", secret, "--calib", filepath.Join(dir, "c")},
			&replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
		{"bad flag", []string{"--nope"}, nil, "usage: fpctl calibrate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var open func() (sensor, string, error)
			if tt.s != nil {
				open = opener(tt.s)
			}
			code, _, errOut := runWith(t, open, append([]string{"calibrate"}, tt.args...)...)
			if code != 1 || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, errOut, tt.want)
			}
		})
	}
}

func TestListAndDeleteArgs(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, make([]byte, 32), 0o600)
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tests := []struct {
		name string
		args []string
		s    *replaySensor
		want string
	}{
		{"list missing secret", []string{"list", "--secret", filepath.Join(dir, "nope")}, nil, "host secret"},
		{"list unpaired", []string{"list", "--secret", secret}, &replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
		{"list extra argument", []string{"list", "x"}, nil, "usage: fpctl list"},
		{"delete without user", []string{"delete"}, nil, "--user is required"},
		{"enroll without finger", []string{"enroll", "--user", me.Username}, nil, "--finger are required"},
		{"enroll unknown finger", []string{"enroll", "--user", me.Username, "--finger", "nose"}, nil, "unknown finger"},
		{"enroll unknown user", []string{"enroll", "--user", "no-such-user-here", "--finger", "left-thumb"}, nil, "no such user"},
		{"enroll unreadable calibration", []string{"enroll", "--user", me.Username, "--finger", "left-thumb", "--calib", dir}, nil, "is a directory"},
		{"enroll unpaired", []string{"enroll", "--user", me.Username, "--finger", "left-thumb", "--secret", secret, "--calib", filepath.Join(dir, "c")},
			&replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
		{"identify unpaired", []string{"identify", "--secret", secret, "--calib", filepath.Join(dir, "c")},
			&replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
		{"identify bad flag", []string{"identify", "--nope"}, nil, "usage: fpctl identify"},
		{"delete unknown finger", []string{"delete", "--user", me.Username, "--finger", "nose"}, nil, "unknown finger"},
		{"delete unknown user", []string{"delete", "--user", "no-such-user-here"}, nil, "no such user"},
		{"delete unpaired", []string{"delete", "--user", me.Uid, "--secret", secret},
			&replaySensor{replies: []string{flashUnpartitioned}}, "not paired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var open func() (sensor, string, error)
			if tt.s != nil {
				open = opener(tt.s)
			}
			code, _, errOut := runWith(t, open, tt.args...)
			if code != 1 || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, errOut, tt.want)
			}
		})
	}
}

func TestUserResolution(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	for _, name := range []string{me.Username, me.Uid} {
		uid, username, err := lookupUser(name)
		if err != nil || strconv.FormatUint(uint64(uid), 10) != me.Uid || username != me.Username {
			t.Errorf("%s: %d %s %v", name, uid, username, err)
		}
	}
	uid, _ := strconv.ParseUint(me.Uid, 10, 32)
	if got := describeSID(validity.UIDSID(uint32(uid))); got != fmt.Sprintf("%s (uid %d)", me.Username, uid) {
		t.Errorf("describe %q", got)
	}
	if got := describeSID(validity.UIDSID(4000000000)); got != "uid 4000000000" {
		t.Errorf("unknown uid %q", got)
	}
	other := validity.SID{Revision: 1, Auth: 5, SubAuth: []uint32{18}}
	if got := describeSID(other); got != "S-1-5-18" {
		t.Errorf("foreign sid %q", got)
	}
}

// fakeFPD answers one request on a fresh socket with the given frames.
func fakeFPD(t *testing.T, frames ...proto.Frame) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fpd.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		proto.Read(c)
		for _, f := range frames {
			proto.Write(c, f.Type, f.Payload)
		}
	}()
	return path
}

func result(r uint32) proto.Frame { return proto.Frame{Type: proto.EvResult, Payload: proto.U32s(r)} }

func finger(uid uint32, sub uint16) proto.Frame {
	return proto.Frame{Type: proto.EvFinger, Payload: proto.U16(proto.U32s(uid), sub)}
}

func runViaFPD(t *testing.T, sock string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	open := func() (sensor, string, error) {
		return nil, "", errors.New("the sensor must not be opened while fpd runs")
	}
	code := run(&env{stdout: &out, stderr: &errOut, open: open, socket: sock}, args)
	return code, out.String(), errOut.String()
}

func TestCommandsViaFPD(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	uid, _ := strconv.ParseUint(me.Uid, 10, 32)
	tests := []struct {
		name   string
		frames []proto.Frame
		args   []string
		code   int
		want   string
	}{
		{"list", []proto.Frame{finger(uint32(uid), 2), finger(uint32(uid), 7), finger(4000000000, 1), result(0)},
			[]string{"list"}, 0, "left-index-finger"},
		{"list empty", []proto.Frame{result(0)}, []string{"list"}, 0, "no users enrolled"},
		{"list busy", []proto.Frame{result(proto.ResultBusy)}, []string{"list"}, 1, "sensor busy"},
		{"enroll", []proto.Frame{{Type: proto.EvPrompt}, {Type: proto.EvProgress, Payload: proto.U32s(1)},
			{Type: proto.EvRetry, Payload: proto.U32s(1)}, result(0)},
			[]string{"enroll", "--user", me.Username, "--finger", "left-thumb"}, 0, "enrolled left-thumb"},
		{"enroll exists", []proto.Frame{result(proto.ResultExists)},
			[]string{"enroll", "--user", me.Username, "--finger", "left-thumb"}, 1, "already enrolled"},
		{"delete all", []proto.Frame{result(0)}, []string{"delete", "--user", me.Username}, 0, "enrolled fingers"},
		{"delete one", []proto.Frame{result(0)}, []string{"delete", "--user", me.Username, "--finger", "left-thumb"}, 0, "left-thumb"},
		{"delete denied", []proto.Frame{result(proto.ResultDenied)}, []string{"delete", "--user", me.Username}, 1, "permission denied"},
		{"identify", []proto.Frame{{Type: proto.EvPrompt}, {Type: proto.EvRetry, Payload: proto.U32s(1)}, finger(uint32(uid), 2), result(0)},
			[]string{"identify"}, 0, "right-index-finger"},
		{"identify no match", []proto.Frame{result(proto.ResultNoMatch)}, []string{"identify"}, 1, "no match"},
		{"identify denied", []proto.Frame{result(proto.ResultDenied)}, []string{"identify"}, 1, "permission denied"},
		{"identify without a finger", []proto.Frame{result(0)}, []string{"identify"}, 1, "without saying whose"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runViaFPD(t, fakeFPD(t, tt.frames...), tt.args...)
			if code != tt.code || !strings.Contains(out+errOut, tt.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q, want %q", code, out, errOut, tt.want)
			}
		})
	}
}
