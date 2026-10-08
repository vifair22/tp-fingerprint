package validity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// calibratedSim pairs a simulated sensor, opens it, and supplies frames
// for calibration captures.
func calibratedSim(t *testing.T) (*simSensor, *Session) {
	t.Helper()
	s, sess := pairedSim(t)
	raw := make([]byte, (3*224+1)*0x78)
	for i := range raw {
		raw[i] = byte(0x70 + (i*31)%48)
	}
	s.frames = func() []byte { return raw }
	return s, sess
}

func TestOpenSensorAndCalibrate(t *testing.T) {
	ctx := context.Background()
	s, sess := calibratedSim(t)

	sen, err := OpenSensor(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sen.linesPerFrame != 224 || !bytes.Equal(sen.factoryValues, simFactoryValues) {
		t.Fatalf("opened sensor: %d lines per frame", sen.linesPerFrame)
	}
	did, err := sen.Calibrate(ctx, false)
	if err != nil || !did {
		t.Fatalf("first calibration: %v, %v", did, err)
	}
	if len(s.captures) != 4 {
		t.Fatalf("%d captures, want 3 passes and the clean slate", len(s.captures))
	}
	calib := sen.CalibrationData()
	if len(calib) != 112*0x78 {
		t.Fatalf("calibration data of %d bytes", len(calib))
	}

	// Partition 6 now holds a clean slate whose header checks out.
	p6 := s.parts[PartitionCalibration]
	n := int(binary.LittleEndian.Uint16(p6[2:]))
	h := sha256.Sum256(p6[cleanSlateHdrLen : cleanSlateHdrLen+n])
	if binary.LittleEndian.Uint16(p6) != cleanSlateMagic || !bytes.Equal(h[:], p6[4:0x24]) {
		t.Fatal("partition 6 does not hold a valid clean slate")
	}

	// A later start with the saved data and that clean slate does nothing.
	s.captures = nil
	sen, err = OpenSensor(sess, calib)
	if err != nil {
		t.Fatal(err)
	}
	if did, err := sen.Calibrate(ctx, false); err != nil || did || len(s.captures) != 0 {
		t.Fatalf("second start: calibrated %v, %d captures, %v", did, len(s.captures), err)
	}

	// A damaged clean slate is replaced; force recalibrates from scratch.
	p6[cleanSlateHdrLen] ^= 1
	if did, err := sen.Calibrate(ctx, false); err != nil || !did {
		t.Fatalf("after damage: %v, %v", did, err)
	}
	s.captures = nil
	if did, err := sen.Calibrate(ctx, true); err != nil || !did || len(s.captures) != 4 {
		t.Fatalf("forced: %v, %d captures, %v", did, len(s.captures), err)
	}
	if !bytes.Equal(sen.CalibrationData(), calib) {
		t.Fatal("forced calibration on the same frames gave different data")
	}
	// Calibrating to the same clean slate leaves the flash unwritten.
	before := strings.Count(strings.Join(s.cmds, " "), "tls:41")
	if _, err := sen.Calibrate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if after := strings.Count(strings.Join(s.cmds, " "), "tls:41"); after != before {
		t.Fatalf("rewrote an identical clean slate (%d writes)", after-before)
	}
}

func TestOpenSensorWithBadSavedCalibration(t *testing.T) {
	_, sess := calibratedSim(t)
	sen, err := OpenSensor(sess, []byte("short"))
	if err != nil {
		t.Fatal(err)
	}
	if sen.CalibrationData() != nil {
		t.Fatal("kept calibration data of the wrong size")
	}
}

func TestCalibrateFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("capture refused", func(t *testing.T) {
		s, sess := calibratedSim(t)
		sen, _ := OpenSensor(sess, nil)
		s.fail = "tls:02"
		if _, err := sen.Calibrate(ctx, false); err == nil {
			t.Fatal("calibrated")
		}
	})
	t.Run("no frame data", func(t *testing.T) {
		s, sess := calibratedSim(t)
		sen, _ := OpenSensor(sess, nil)
		s.frames = nil
		if _, err := sen.Calibrate(ctx, false); err == nil {
			t.Fatal("calibrated")
		}
	})
	t.Run("short frame data", func(t *testing.T) {
		s, sess := calibratedSim(t)
		sen, _ := OpenSensor(sess, nil)
		s.frames = func() []byte { return make([]byte, 100) }
		if _, err := sen.Calibrate(ctx, false); !errors.Is(err, ErrShortReply) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		_, sess := calibratedSim(t)
		sen, _ := OpenSensor(sess, nil)
		c, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := sen.Calibrate(c, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("flash write refused", func(t *testing.T) {
		s, sess := calibratedSim(t)
		sen, _ := OpenSensor(sess, nil)
		s.fail = "tls:41"
		if _, err := sen.Calibrate(ctx, false); err == nil || !strings.Contains(err.Error(), "clean slate") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestOpenSensorRejects(t *testing.T) {
	tests := []struct {
		name  string
		setup func(s *simSensor)
		want  string
	}{
		{"identify refused", func(s *simSensor) { s.fail = "tls:75" }, "0x75"},
		{"rom refused", func(s *simSensor) { s.fail = "tls:01" }, "0x01"},
		{"factory bits refused", func(s *simSensor) { s.fail = "tls:6f" }, "0x6f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, sess := calibratedSim(t)
			tt.setup(s)
			if _, err := OpenSensor(sess, nil); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := lookupSensorType(0x190, 0x4b); !errors.Is(err, ErrUnsupportedSensor) {
		t.Fatalf("other model: %v", err)
	}
	if typ, err := lookupSensorType(0x190, 0x4a); err != nil || typ.Type != 0x199 {
		t.Fatalf("this model: %v, %v", typ, err)
	}
}

func TestParseFactoryBits(t *testing.T) {
	good := (&simSensor{}).factoryBits()
	bits, err := parseFactoryBits(good)
	if err != nil || len(bits) != 2 || !bytes.Equal(bits[3][4:], simFactoryValues) {
		t.Fatalf("%v, %v", bits, err)
	}
	for name, p := range map[string][]byte{
		"short header":  good[:4],
		"short entry":   good[:12],
		"short value":   good[:30],
		"trailing junk": append(append([]byte(nil), good...), 1),
	} {
		if _, err := parseFactoryBits(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeInsn(t *testing.T) {
	tests := []struct {
		in   string
		op   int
		size int
		args [3]int
	}{
		{"00", 0, 1, [3]int{}},
		{"04", tsEndOfData, 1, [3]int{}},
		{"0603", tsEnableRx, 2, [3]int{3}},
		{"0700", 7, 2, [3]int{0x100}},
		{"0905", 8, 2, [3]int{0x105}},
		{"0b05", 9, 2, [3]int{0x105}},
		{"0e", 10, 1, [3]int{2}},
		{"131000", tsCall, 3, [3]int{3, 0x40, 0x100}},
		{"25", 12, 1, [3]int{5}},
		{"4f3412", tsRegWrite, 3, [3]int{0x8000203c, 0x1234}},
		{"9a", 14, 1, [3]int{3, 2}},
		{"d100", 15, 2, [3]int{2, 1, 0x100}},
	}
	for _, tt := range tests {
		in, err := decodeInsn(mustHex(tt.in))
		if err != nil || in.op != tt.op || in.size != tt.size || in.args != tt.args {
			t.Errorf("%s: %+v, %v", tt.in, in, err)
		}
	}
	for _, bad := range []string{"", "05", "07", "08", "0a", "10", "40", "c0", "18"} {
		if _, err := decodeInsn(mustHex(bad)); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	if _, err := findNthInsn(mustHex("0001"), tsEnableRx, 1); err == nil {
		t.Error("found a missing instruction")
	}
	if _, err := findNthInsn(mustHex("0006"), tsEnableRx, 1); err == nil {
		t.Error("decoded a truncated table")
	}
}

func TestPatchTimeslotTable(t *testing.T) {
	got, err := patchTimeslotTable(mustHex("00"+"131002"+"0705"+"130401"+"ff"+"131002"), true, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Calls with a repeat over 1 are doubled and their address bumped;
	// scanning stops at the first unknown byte.
	if want := "00" + "131104" + "0705" + "130401" + "ff" + "131002"; hexOf(got) != want {
		t.Fatalf("got %s, want %s", hexOf(got), want)
	}
	if _, err := patchTimeslotTable(mustHex("1310ff00"), true, 2); err == nil {
		t.Error("repeat overflow accepted")
	}
	if _, err := patchTimeslotTable(mustHex("13ff0200"), true, 2); err == nil {
		t.Error("address overflow accepted")
	}
}

func TestSplitChunksErrors(t *testing.T) {
	for _, bad := range []string{"01", "0100050001"} {
		if _, err := splitChunks(mustHex(bad)); !errors.Is(err, ErrShortReply) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

func TestBitpackAllEqual(t *testing.T) {
	if _, _, _, err := bitpack([]byte{5, 5, 5}); err == nil {
		t.Fatal("packed equal values")
	}
}

type errTransport struct{ err error }

func (e errTransport) Bulk(uint8, []byte, time.Duration) (int, error) { return 0, e.err }

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func TestWaitIntAndReadData(t *testing.T) {
	s := newTLSSensor(t)
	l := NewLink(s, nil)
	ctx := context.Background()
	s.ints = [][]byte{{2, 0, 0}}
	if b, err := l.WaitInt(ctx); err != nil || !bytes.Equal(b, []byte{2, 0, 0}) {
		t.Fatalf("%x, %v", b, err)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := l.WaitInt(c); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
	s.data = []byte{9, 9}
	if b, err := l.ReadData(); err != nil || !bytes.Equal(b, []byte{9, 9}) {
		t.Fatalf("%x, %v", b, err)
	}
	if _, err := l.ReadData(); err == nil {
		t.Fatal("read data that was not there")
	}
	boom := errors.New("boom")
	if _, err := NewLink(errTransport{boom}, nil).WaitInt(ctx); !errors.Is(err, boom) {
		t.Fatalf("transport error: %v", err)
	}
	if !isTimeout(timeoutErr{}) || isTimeout(boom) {
		t.Fatal("isTimeout")
	}
}
