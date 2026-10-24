package crosfp_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"git.airies.net/vifair22/tp-fingerprint/internal/crosfp"
	"git.airies.net/vifair22/tp-fingerprint/internal/crosfp/crosfptest"
)

func TestResultError(t *testing.T) {
	tests := []struct {
		r    crosfp.Result
		want string
	}{
		{crosfp.ResultBusy, "fpmcu: busy"},
		{crosfp.ResultInvalidVersion, "fpmcu: invalid version"},
		{crosfp.Result(99), "fpmcu: result 99"},
	}
	for _, tt := range tests {
		if got := tt.r.Error(); got != tt.want {
			t.Errorf("Result(%d).Error() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestEventFields(t *testing.T) {
	e := crosfp.EventMatch | crosfp.Event(3) | crosfp.Event(2<<12) | crosfp.Event(40<<4)
	if e.Code() != 3 || e.MatchIndex() != 2 || e.Progress() != 40 {
		t.Fatalf("code %d index %d progress %d", e.Code(), e.MatchIndex(), e.Progress())
	}
}

func TestInfoAndSeed(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	info, err := m.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.TemplateSize != 5156 || info.TemplateMax != 5 || info.TemplateVersion != 4 || info.VendorID != 0x20435046 {
		t.Fatalf("info %+v", info)
	}
	set, err := m.SeedSet()
	if err != nil || set {
		t.Fatalf("seed set %v err %v before setting", set, err)
	}
	var seed [crosfp.SeedSize]byte
	seed[0] = 7
	if err := m.SetSeed(seed); err != nil {
		t.Fatal(err)
	}
	if set, _ := m.SeedSet(); !set {
		t.Fatal("seed not reported set")
	}
	if err := m.SetSeed(seed); !errors.Is(err, crosfp.ResultAccessDenied) {
		t.Fatalf("second seed: %v, want access denied", err)
	}
	v, err := m.CommandVersions(0x0406)
	if err != nil || v != 2 {
		t.Fatalf("versions %#x err %v", v, err)
	}
}

func TestContextPollsWhileBusy(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	f.Templates = [][]byte{{1}}
	var user [crosfp.UserIDSize]byte
	user[0] = 1
	if err := m.SetContext(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if len(f.Templates) != 0 || f.Context[0] != 1 {
		t.Fatalf("context did not clear the templates: %v", f)
	}
}

func TestContextCancelled(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.SetContext(ctx, [crosfp.UserIDSize]byte{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want cancelled", err)
	}
}

func TestTemplateRoundTrip(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	_ = m.SetSeed([crosfp.SeedSize]byte{1})
	_ = m.SetContext(context.Background(), [crosfp.UserIDSize]byte{2})
	blob := append(append(append([]byte{}, f.Seed...), f.Context...), []byte("print:a;")...)
	blob = append(blob, bytes.Repeat([]byte{9}, 5156-len(blob))...)
	// 600-byte packets: the upload has to go in several chunks.
	if err := m.UploadTemplate(blob); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadTemplate(0, 5156)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatal("template read back differs")
	}
	if _, err := m.ReadTemplate(15, 10); err == nil {
		t.Fatal("index 15 accepted")
	}
	if _, err := m.ReadTemplate(3, 10); !errors.Is(err, crosfp.ResultInvalidParam) {
		t.Fatalf("missing template: %v", err)
	}
}

func TestUploadRefusedUnderAnotherKey(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	_ = m.SetSeed([crosfp.SeedSize]byte{1})
	if err := m.UploadTemplate(make([]byte, 100)); !errors.Is(err, crosfp.ResultInvalidParam) {
		t.Fatalf("err %v, want invalid param", err)
	}
}

func TestModeAndWait(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	if mode, err := m.Mode(); err != nil || mode != 0 {
		t.Fatalf("mode %#x err %v", mode, err)
	}
	if _, err := m.SetMode(crosfp.ModeFingerUp); err != nil {
		t.Fatal(err)
	}
	e, err := m.Wait(context.Background(), crosfp.EventFingerUp)
	if err != nil || e&crosfp.EventFingerUp == 0 {
		t.Fatalf("event %#x err %v", e, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.Wait(ctx, crosfp.EventMatch); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait with no event: %v", err)
	}
}

func TestCommandFailures(t *testing.T) {
	f := crosfptest.New()
	m := crosfp.New(f)
	f.Fail[0x0403] = crosfp.ResultError
	f.Fail[0x0409] = crosfp.ResultError
	f.Fail[0x0402] = crosfp.ResultError
	f.Fail[0x0008] = crosfp.ResultError
	if _, err := m.Info(); err == nil {
		t.Error("Info succeeded")
	}
	if _, err := m.SeedSet(); err == nil {
		t.Error("SeedSet succeeded")
	}
	if _, err := m.SetMode(0); err == nil {
		t.Error("SetMode succeeded")
	}
	if _, err := m.CommandVersions(1); err == nil {
		t.Error("CommandVersions succeeded")
	}
	f.Fail[0x0406] = crosfp.ResultError
	if err := m.SetContext(context.Background(), [crosfp.UserIDSize]byte{}); err == nil {
		t.Error("SetContext succeeded")
	}
	f.Fail[0x0405] = crosfp.ResultError
	if err := m.UploadTemplate([]byte{1}); err == nil {
		t.Error("UploadTemplate succeeded")
	}
	if m.Transport() != f {
		t.Error("Transport is not the fake")
	}
}

// short answers commands with less than asked for.
type short struct{}

func (short) Command(uint32, uint32, []byte, int) ([]byte, error) { return []byte{1}, nil }
func (short) NextEvent(context.Context) (crosfp.Event, error)     { return 0, errors.New("none") }
func (short) Close() error                                        { return nil }

func TestShortResponses(t *testing.T) {
	m := crosfp.New(&short{})
	if _, err := m.Info(); err == nil {
		t.Error("short Info accepted")
	}
	if _, err := m.SeedSet(); err == nil {
		t.Error("short SeedSet accepted")
	}
	if _, err := m.SetMode(0); err == nil {
		t.Error("short SetMode accepted")
	}
	if _, err := m.CommandVersions(1); err == nil {
		t.Error("short CommandVersions accepted")
	}
	if _, err := m.ReadTemplate(0, 10); err == nil {
		t.Error("short ReadTemplate accepted")
	}
}
