package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
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
	code := run(&env{stdout: &out, stderr: &errOut, open: open}, args)
	return code, out.String(), errOut.String()
}

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
