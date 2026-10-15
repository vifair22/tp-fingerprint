package crosdev

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/crosfp"
	"git.airies.net/vifair22/t480-fingerprint/internal/crosfp/crosfptest"
	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
)

func setup(t *testing.T) (*Device, *crosfptest.MCU) {
	t.Helper()
	dir := t.TempDir()
	mcu := crosfptest.New()
	d := New(Config{
		SecretPath: filepath.Join(dir, "host-secret"),
		StoreDir:   filepath.Join(dir, "crosfp"),
		Open:       func(string) (crosfp.Transport, error) { return mcu, nil },
	})
	return d, mcu
}

func enroll(t *testing.T, d *Device, mcu *crosfptest.MCU, uid uint32, sub uint16, finger string) {
	t.Helper()
	for i := 0; i < mcu.EnrollSteps; i++ {
		mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: finger})
	}
	var got []int
	err := d.Enroll(context.Background(), uid, sub, func() {}, func(n int, err error) {
		if err == nil {
			got = append(got, n)
		}
	})
	if err != nil {
		t.Fatalf("enroll %s: %v", finger, err)
	}
	if len(got) != mcu.EnrollSteps || got[len(got)-1] != mcu.EnrollSteps {
		t.Fatalf("progress %v", got)
	}
}

func TestWarmSetsTheSeedOnce(t *testing.T) {
	d, mcu := setup(t)
	if err := d.Warm(); err != nil {
		t.Fatal(err)
	}
	if mcu.Seed == nil || mcu.Context == nil {
		t.Fatal("no seed or context")
	}
	// A restarted fpd finds the seed set and does not set another.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d2 := New(d.cfg)
	if err := d2.Warm(); err != nil {
		t.Fatal(err)
	}
	if mcu.SeedCalls != 1 {
		t.Fatalf("seed set %d times", mcu.SeedCalls)
	}
}

func TestEnrollVerifyIdentify(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 2, "alice-index")
	enroll(t, d, mcu, 1001, 7, "bob-index")

	tests := []struct {
		name   string
		uid    uint32
		touch  string
		want   bool
		retrys int
	}{
		{"own finger", 1000, "alice-index", true, 0},
		{"someone else's finger", 1000, "bob-index", false, 0},
		{"unknown finger", 1001, "stranger", false, 0},
		{"after a bad touch", 1001, "bob-index", true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.retrys; i++ {
				mcu.Touches = append(mcu.Touches, crosfptest.Touch{Code: crosfp.MatchNoLowQuality})
			}
			mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: tt.touch})
			retries := 0
			ok, err := d.Verify(context.Background(), tt.uid, func() {}, func() { retries++ })
			if err != nil || ok != tt.want || retries != tt.retrys {
				t.Fatalf("ok %v err %v retries %d", ok, err, retries)
			}
		})
	}

	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "bob-index"})
	who, found, err := d.Identify(context.Background(), func() {}, func() {})
	if err != nil || !found || who.UID != 1001 || who.Subtype != 7 {
		t.Fatalf("identify %+v %v %v", who, found, err)
	}
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "stranger"})
	if _, found, err := d.Identify(context.Background(), func() {}, func() {}); err != nil || found {
		t.Fatalf("stranger identified: %v %v", found, err)
	}
}

func TestVerifyWithNothingEnrolled(t *testing.T) {
	d, _ := setup(t)
	if _, err := d.Verify(context.Background(), 1000, func() { t.Fatal("prompted") }, func() {}); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("err %v", err)
	}
	if _, _, err := d.Identify(context.Background(), func() { t.Fatal("prompted") }, func() {}); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("err %v", err)
	}
}

func TestEnrollRules(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	if err := d.Enroll(context.Background(), 1000, 1, func() {}, func(int, error) {}); !errors.Is(err, server.ErrExists) {
		t.Fatalf("re-enroll: %v", err)
	}
	for i, f := range []string{"b", "c", "d", "e"} {
		enroll(t, d, mcu, 1000, uint16(2+i), f)
	}
	if err := d.Enroll(context.Background(), 1000, 9, func() {}, func(int, error) {}); !errors.Is(err, ErrFull) {
		t.Fatalf("sixth finger: %v", err)
	}
}

func TestEnrollRejectedTouches(t *testing.T) {
	d, mcu := setup(t)
	mcu.Touches = []crosfptest.Touch{
		{Code: crosfp.EnrollLowQuality}, {Finger: "a"}, {Code: crosfp.EnrollImmobile},
		{Finger: "a"}, {Code: crosfp.EnrollLowCoverage}, {Finger: "a"}, {Finger: "a"},
	}
	var errs []error
	err := d.Enroll(context.Background(), 1, 1, func() {}, func(_ int, err error) {
		if err != nil {
			errs = append(errs, err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []error{ErrLowQuality, ErrImmobile, ErrLowCoverage}
	if len(errs) != len(want) {
		t.Fatalf("errors %v", errs)
	}
	for i := range want {
		if !errors.Is(errs[i], want[i]) {
			t.Errorf("touch error %d: %v, want %v", i, errs[i], want[i])
		}
	}
}

func TestEnrollCancelled(t *testing.T) {
	d, mcu := setup(t)
	mcu.Touches = []crosfptest.Touch{{Finger: "a"}} // one touch, then nothing
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.Enroll(ctx, 1, 1, func() {}, func(int, error) {}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if mcu.Mode != 0 {
		t.Fatalf("left the MCU in mode %#x", mcu.Mode)
	}
	if l, _ := d.List(proto.AllUsers); len(l) != 0 {
		t.Fatalf("a cancelled enrollment was stored: %v", l)
	}
}

func TestListAndDelete(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	enroll(t, d, mcu, 1000, 2, "b")
	enroll(t, d, mcu, 1001, 1, "c")
	if l, _ := d.List(1000); len(l) != 2 {
		t.Fatalf("list 1000: %v", l)
	}
	if l, _ := d.List(proto.AllUsers); len(l) != 3 {
		t.Fatalf("list all: %v", l)
	}
	if err := d.Delete(1000, 2); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(1000, 2); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("second delete: %v", err)
	}
	// The next request reloads: the MCU then holds a and c, in order.
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "c"})
	ok, err := d.Verify(context.Background(), 1001, func() {}, func() {})
	if err != nil || !ok {
		t.Fatalf("verify after delete: %v %v", ok, err)
	}
	if f := mcu.Fingers(); len(f) != 2 || f[0] != "a" || f[1] != "c" {
		t.Fatalf("MCU holds %v", f)
	}
	if err := d.Delete(1000, 0); err != nil {
		t.Fatal(err)
	}
	if l, _ := d.List(1000); len(l) != 0 {
		t.Fatalf("all of 1000 not deleted: %v", l)
	}
}

func TestReloadAfterMCUReset(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// The MCU rebooted: no seed, no templates. fpd sets the same seed, so
	// the stored template loads again.
	mcu.Seed, mcu.Context, mcu.Templates = nil, nil, nil
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	ok, err := d.Verify(context.Background(), 1000, func() {}, func() {})
	if err != nil || !ok {
		t.Fatalf("verify after reset: %v %v", ok, err)
	}
}

func TestRebootWhileOpen(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	// The MCU rebooted under an open handle, as across a suspend: the
	// request finds it out before scanning and reloads, so it succeeds.
	mcu.Seed, mcu.Context, mcu.Templates = nil, nil, nil
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	ok, err := d.Verify(context.Background(), 1000, func() {}, func() {})
	if err != nil || !ok {
		t.Fatalf("verify after a reboot under the handle: %v %v", ok, err)
	}
	mcu.Seed, mcu.Context, mcu.Templates = nil, nil, nil
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	e, ok, err := d.Identify(context.Background(), func() {}, func() {})
	if err != nil || !ok || e.UID != 1000 {
		t.Fatalf("identify after a reboot under the handle: %v %v %v", e, ok, err)
	}
}

func TestOneFailedModeIsRetried(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	mcu.FailOnce = map[uint32]crosfp.Result{0x0402: crosfp.Result(1)}
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	ok, err := d.Verify(context.Background(), 1000, func() {}, func() {})
	if err != nil || !ok {
		t.Fatalf("verify after one failed SetMode: %v %v", ok, err)
	}
	// A sensor that keeps failing is still reported, after one retry.
	mcu.Fail = map[uint32]crosfp.Result{0x0402: crosfp.Result(1)}
	if _, err := d.Verify(context.Background(), 1000, func() {}, func() {}); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
}

func TestForeignSeedIsReported(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	_ = d.Close()
	mcu.Seed = []byte("someone else's seed, set first..")
	mcu.Templates = nil
	err := d.Warm()
	if err == nil {
		t.Fatal("templates loaded under another seed")
	}
	if l, _ := d.List(1000); len(l) != 1 {
		t.Fatal("the stored template was deleted")
	}
}

func TestMatchUpdatesTheTemplate(t *testing.T) {
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	file := filepath.Join(d.cfg.StoreDir, fileName(1000, 1))
	before, _ := os.ReadFile(file)
	mcu.Templates[0][len(mcu.Templates[0])-1] = 0x5a // the MCU refines it
	mcu.UpdateOnMatch = true
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	if ok, err := d.Verify(context.Background(), 1000, func() {}, func() {}); err != nil || !ok {
		t.Fatalf("verify %v %v", ok, err)
	}
	after, _ := os.ReadFile(file)
	if string(before) == string(after) || after[len(after)-1] != 0x5a {
		t.Fatal("updated template not stored")
	}
}

func TestMatchFailures(t *testing.T) {
	tests := []struct {
		name string
		code uint32
	}{
		{"internal error", crosfp.MatchNoInternal},
		{"auth failure", crosfp.MatchNoAuthFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, mcu := setup(t)
			enroll(t, d, mcu, 1000, 1, "a")
			mcu.Touches = append(mcu.Touches, crosfptest.Touch{Code: tt.code})
			if _, err := d.Verify(context.Background(), 1000, func() {}, func() {}); err == nil {
				t.Fatal("no error")
			}
		})
	}
	d, mcu := setup(t)
	enroll(t, d, mcu, 1000, 1, "a")
	mcu.Templates = nil // the MCU lost them behind fpd's back
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	if _, err := d.Verify(context.Background(), 1000, func() {}, func() {}); !errors.Is(err, server.ErrNotEnrolled) {
		t.Fatalf("err %v", err)
	}
}

func TestUnavailable(t *testing.T) {
	dir := t.TempDir()
	d := New(Config{SecretPath: filepath.Join(dir, "s"), StoreDir: dir,
		Open: func(string) (crosfp.Transport, error) { return nil, os.ErrNotExist }})
	if err := d.Warm(); !errors.Is(err, server.ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWrongFormatRefused(t *testing.T) {
	d, mcu := setup(t)
	mcu.Format = 3
	if err := d.Warm(); !errors.Is(err, ErrFormat) {
		t.Fatalf("err %v", err)
	}
	if !mcu.Closed {
		t.Fatal("transport left open")
	}
}

func TestFailuresOnTheWayUp(t *testing.T) {
	for _, cmd := range []uint32{0x0403, 0x0409, 0x0408, 0x0406} {
		d, mcu := setup(t)
		mcu.Fail[cmd] = crosfp.ResultError
		if err := d.Warm(); err == nil {
			t.Errorf("Warm with command 0x%04x failing succeeded", cmd)
		}
	}
}

func TestNames(t *testing.T) {
	tests := []struct {
		name string
		uid  uint32
		sub  uint16
		ok   bool
	}{
		{"1000-2.tpl", 1000, 2, true},
		{"1000-2.tmp", 0, 0, false},
		{"x-2.tpl", 0, 0, false},
		{"1000.tpl", 0, 0, false},
		{"1000-70000.tpl", 0, 0, false},
	}
	for _, tt := range tests {
		uid, sub, ok := parseName(tt.name)
		if ok != tt.ok || uid != tt.uid || sub != tt.sub {
			t.Errorf("%s: %d %d %v", tt.name, uid, sub, ok)
		}
	}
	if fileName(5, 6) != "5-6.tpl" {
		t.Error(fileName(5, 6))
	}
}

func TestPresent(t *testing.T) {
	if Present(filepath.Join(t.TempDir(), "none")) {
		t.Error("missing path present")
	}
	if !Present("/dev/null") {
		t.Error("/dev/null not a character device")
	}
}

func TestSensorSleepsBetweenRequests(t *testing.T) {
	d, mcu := setup(t)
	if err := d.Warm(); err != nil {
		t.Fatal(err)
	}
	if mcu.Mode != crosfp.ModeDeepSleep {
		t.Fatalf("after warm: mode %#x, want deep sleep", mcu.Mode)
	}
	enroll(t, d, mcu, 1000, 1, "a")
	if mcu.Mode != crosfp.ModeDeepSleep {
		t.Fatalf("after enroll: mode %#x, want deep sleep", mcu.Mode)
	}
	mcu.Touches = append(mcu.Touches, crosfptest.Touch{Finger: "a"})
	if ok, err := d.Verify(context.Background(), 1000, func() {}, func() {}); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if mcu.Mode != crosfp.ModeDeepSleep {
		t.Fatalf("after verify: mode %#x, want deep sleep", mcu.Mode)
	}
}
