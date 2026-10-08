package validity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

// exchange is one scripted command: the request the sensor expects and
// the reply it gives.
type exchange struct {
	req string // hex
	rsp string // hex
}

// fakeSensor replays a script of exchanges and fails the test on any
// request it was not told to expect.
type fakeSensor struct {
	t        *testing.T
	script   []exchange
	pending  []byte
	writeErr error
	readErr  error
	short    bool // report one byte fewer written than asked
}

func (f *fakeSensor) Bulk(ep uint8, buf []byte, _ time.Duration) (int, error) {
	f.t.Helper()
	switch ep {
	case epCmdOut:
		if f.writeErr != nil {
			return 0, f.writeErr
		}
		if len(f.script) == 0 {
			f.t.Fatalf("unexpected command %x", buf)
		}
		next := f.script[0]
		f.script = f.script[1:]
		if got := hex.EncodeToString(buf); got != next.req {
			f.t.Fatalf("command = %s, want %s", got, next.req)
		}
		f.pending = unhex(f.t, next.rsp)
		if f.short {
			return len(buf) - 1, nil
		}
		return len(buf), nil
	case epCmdIn:
		if f.readErr != nil {
			return 0, f.readErr
		}
		return copy(buf, f.pending), nil
	}
	f.t.Fatalf("unexpected endpoint 0x%02x", ep)
	return 0, nil
}

func (f *fakeSensor) done() {
	f.t.Helper()
	if len(f.script) != 0 {
		f.t.Fatalf("%d scripted exchanges not used", len(f.script))
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestLink(f *fakeSensor) (*Link, *[]time.Duration) {
	l := NewLink(f, nil)
	var slept []time.Duration
	l.sleep = func(d time.Duration) { slept = append(slept, d) }
	return l, &slept
}

// From the comment in python-validity's flash.py: a real 4302 reply.
const fwextReply = "0000" +
	"0100 0100 0800 c28c745a" +
	"0100 3446 0200 0700 d03e0000" +
	"0100 8408 0100 0700 00040000" +
	"0200 8428 0300 1200 e0100000" +
	"0200 7636 0100 0c00 100a0000" +
	"0100 8647 0000 0100 505a0000" +
	"0200 2377 0000 0100 802f0000" +
	"0200 6637 0100 0c00 f0220200" +
	"0100 2556 0000 0100 60040000"

func TestCmdBusyRetry(t *testing.T) {
	tests := []struct {
		name      string
		busy      int
		wantSt    Status
		wantSleep int
	}{
		{"no busy", 0, StatusOK, 0},
		{"busy then ok", 3, StatusOK, 3},
		{"busy until the last attempt", busyAttempts - 1, StatusOK, busyAttempts - 1},
		{"busy throughout", busyAttempts, StatusBusy, busyAttempts - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t}
			for range tt.busy {
				f.script = append(f.script, exchange{"01", "0401"})
			}
			if tt.busy < busyAttempts {
				f.script = append(f.script, exchange{"01", "0000aa"})
			}
			l, slept := newTestLink(f)
			st, _, err := l.Cmd([]byte{0x01})
			if err != nil {
				t.Fatal(err)
			}
			if st != tt.wantSt {
				t.Fatalf("status = %v, want %v", st, tt.wantSt)
			}
			if len(*slept) != tt.wantSleep {
				t.Fatalf("slept %d times, want %d", len(*slept), tt.wantSleep)
			}
			for _, d := range *slept {
				if d != busyDelay {
					t.Fatalf("slept %v, want %v", d, busyDelay)
				}
			}
			f.done()
		})
	}
}

func TestLinkErrors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name string
		f    *fakeSensor
		req  []byte
		want error
	}{
		{"write error", &fakeSensor{writeErr: boom}, []byte{0x01}, boom},
		{"read error", &fakeSensor{readErr: boom, script: []exchange{{"01", ""}}}, []byte{0x01}, boom},
		{"short write", &fakeSensor{short: true, script: []exchange{{"0102", "0000"}}}, []byte{0x01, 0x02}, nil},
		{"one-byte reply", &fakeSensor{script: []exchange{{"01", "00"}}}, []byte{0x01}, ErrShortReply},
		{"empty command", &fakeSensor{}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.t = t
			l, _ := newTestLink(tt.f)
			_, _, err := l.Cmd(tt.req)
			if err == nil {
				t.Fatal("expected an error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCmdOKStatusError(t *testing.T) {
	f := &fakeSensor{t: t, script: []exchange{{"19", "4f04"}}}
	l, _ := newTestLink(f)
	_, err := l.CmdOK([]byte{0x19})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != StatusSignature || se.Cmd != 0x19 {
		t.Fatalf("err = %v, want signature StatusError for 0x19", err)
	}
	if !strings.Contains(err.Error(), "signature validation failed") {
		t.Fatalf("message %q", err)
	}
}

func TestLinkTrace(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f := &fakeSensor{t: t, script: []exchange{{"01", "0401"}, {"01", "0000"}}}
	l := NewLink(f, log)
	l.sleep = func(time.Duration) {}
	if _, err := l.CmdOK([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cmd >", "data=01", "data=0401", "sensor busy"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("trace lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestStatusString(t *testing.T) {
	tests := map[Status]string{
		StatusOK: "ok", StatusBusy: "busy", StatusSignature: "signature validation failed",
		StatusNoFirmware: "no firmware", StatusNoPartition: "no partition", 0x1234: "0x1234",
	}
	for st, want := range tests {
		if st.String() != want {
			t.Errorf("%#x: %q, want %q", uint16(st), st.String(), want)
		}
	}
}

func TestParseRomInfo(t *testing.T) {
	p := unhex(t, "78563412 0d000000 06 07 ff 9a 000000 05")
	got, err := parseRomInfo(p)
	if err != nil {
		t.Fatal(err)
	}
	want := RomInfo{Timestamp: 0x12345678, Build: 13, Major: 6, Minor: 7, Product: 0x9a, Unknown1: 5}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if _, err := parseRomInfo(p[:15]); !errors.Is(err, ErrShortReply) {
		t.Fatalf("short: %v", err)
	}
}

func TestParseFlashInfo(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    FlashInfo
		wantErr bool
	}{
		{name: "uninitialised", payload: "", want: FlashInfo{Uninitialised: true}},
		{
			name:    "formatted, no partitions",
			payload: "ef00 4014 0001 0000 0010 0000 0000",
			want: FlashInfo{JedecID0: 0xef, JedecID1: 0x1440, Blocks: 0x100,
				BlockSize: 0x1000, Partitions: []Partition{}},
		},
		{
			name: "two partitions",
			payload: "ef00 4014 0001 0000 0010 0000 0200" +
				"01 02 0300 00100000 00200000" +
				"02 03 0700 00300000 00400000",
			want: FlashInfo{JedecID0: 0xef, JedecID1: 0x1440, Blocks: 0x100, BlockSize: 0x1000,
				Partitions: []Partition{
					{ID: 1, Type: 2, AccessLvl: 3, Offset: 0x1000, Size: 0x2000},
					{ID: 2, Type: 3, AccessLvl: 7, Offset: 0x3000, Size: 0x4000},
				}},
		},
		{name: "short header", payload: "ef00 4014", wantErr: true},
		{name: "truncated table", payload: "ef00 4014 0001 0000 0010 0000 0200 01020300", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFlashInfo(unhex(t, tt.payload))
			if tt.wantErr {
				if !errors.Is(err, ErrShortReply) {
					t.Fatalf("err = %v, want ErrShortReply", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetFirmwareInfo(t *testing.T) {
	tests := []struct {
		name    string
		rsp     string
		wantNil bool
		wantErr bool
	}{
		{name: "reference reply", rsp: fwextReply},
		{name: "no firmware", rsp: "b004", wantNil: true},
		{name: "no partition", rsp: "af04", wantNil: true},
		{name: "other status", rsp: "4f04", wantErr: true},
		{name: "short header", rsp: "0000 0100", wantErr: true},
		{name: "truncated modules", rsp: "0000 0100 0100 0200 c28c745a 0100", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: []exchange{{"4302", tt.rsp}}}
			l, _ := newTestLink(f)
			fi, _, err := GetFirmwareInfo(l, PartitionFwext)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantNil {
				if fi != nil {
					t.Fatalf("got %+v, want nil", fi)
				}
				return
			}
			if fi.Major != 1 || fi.Minor != 1 || fi.BuildTime != 0x5a748cc2 || len(fi.Modules) != 8 {
				t.Fatalf("header %+v", fi)
			}
			want := Module{Type: 1, Subtype: 0x4634, Major: 2, Minor: 7, Size: 0x3ed0}
			if fi.Modules[0] != want {
				t.Fatalf("module 0 = %+v, want %+v", fi.Modules[0], want)
			}
			f.done()
		})
	}
}

func TestProbe(t *testing.T) {
	rom := "0000 78563412 0d000000 06 07 ff 9a 000000 05"
	t.Run("clean sensor after a busy start", func(t *testing.T) {
		f := &fakeSensor{t: t, script: []exchange{
			{"3e", "0401"}, {"3e", "0000"},
			{"01", rom},
			{"19", "0000 cafe"},
			{"4302", "b004"},
		}}
		l, _ := newTestLink(f)
		r, err := Probe(l)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Flash.Uninitialised || r.Rom.Build != 13 || r.Fwext != nil || r.FwextStatus != StatusNoFirmware ||
			!bytes.Equal(r.Cmd19, []byte{0xca, 0xfe}) {
			t.Fatalf("report %+v", r)
		}
		f.done()
	})
	t.Run("loaded firmware", func(t *testing.T) {
		f := &fakeSensor{t: t, script: []exchange{
			{"3e", "0000 ef00 4014 0001 0000 0010 0000 0000"},
			{"01", rom}, {"19", "0000"}, {"4302", fwextReply},
		}}
		l, _ := newTestLink(f)
		r, err := Probe(l)
		if err != nil {
			t.Fatal(err)
		}
		if r.Flash.Uninitialised || r.Fwext == nil || len(r.Fwext.Modules) != 8 {
			t.Fatalf("report %+v", r)
		}
	})
	failures := []struct {
		name   string
		script []exchange
	}{
		{"flash", []exchange{{"3e", "0100"}}},
		{"rom", []exchange{{"3e", "0000"}, {"01", "0100"}}},
		{"cmd19", []exchange{{"3e", "0000"}, {"01", rom}, {"19", "0100"}}},
		{"fwext", []exchange{{"3e", "0000"}, {"01", rom}, {"19", "0000"}, {"4302", "0100"}}},
	}
	for _, tt := range failures {
		t.Run("fails at "+tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: tt.script}
			l, _ := newTestLink(f)
			if _, err := Probe(l); err == nil {
				t.Fatal("expected an error")
			}
			f.done()
		})
	}
}
