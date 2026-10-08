package proto

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The C header must define every constant pam_fpd uses with the value
// Go has.
func TestHeaderMatches(t *testing.T) {
	src, err := os.ReadFile("../../pam/include/fpd_proto.h")
	if err != nil {
		t.Fatal(err)
	}
	defs := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^#define (FPD_\w+) (\S+)`).FindAllStringSubmatch(string(src), -1) {
		defs[m[1]] = m[2]
	}
	num := func(name string) uint64 {
		t.Helper()
		v, ok := defs[name]
		if !ok {
			t.Fatalf("%s missing from the header", name)
		}
		n, err := strconv.ParseUint(regexp.MustCompile(`[uU]$`).ReplaceAllString(v, ""), 0, 32)
		if err != nil {
			t.Fatalf("%s = %s: %v", name, v, err)
		}
		return n
	}
	want := map[string]uint64{
		"FPD_FRAME_HEADER_LEN":    HeaderLen,
		"FPD_REQ_VERIFY":          uint64(ReqVerify),
		"FPD_REQ_VERIFY_LEN":      VerifyLen,
		"FPD_TIMEOUT_NONE":        TimeoutNone,
		"FPD_EV_PROMPT":           uint64(EvPrompt),
		"FPD_EV_PROMPT_LEN":       PromptLen,
		"FPD_EV_RETRY":            uint64(EvRetry),
		"FPD_EV_RETRY_LEN":        RetryLen,
		"FPD_EV_RESULT":           uint64(EvResult),
		"FPD_EV_RESULT_LEN":       ResultLen,
		"FPD_RETRY_SCAN":          uint64(RetryScan),
		"FPD_RETRY_NO_MATCH":      uint64(RetryNoMatch),
		"FPD_RESULT_MATCH":        uint64(ResultMatch),
		"FPD_RESULT_NO_MATCH":     uint64(ResultNoMatch),
		"FPD_RESULT_NOT_ENROLLED": uint64(ResultNotEnrolled),
		"FPD_RESULT_UNAVAILABLE":  uint64(ResultUnavailable),
		"FPD_RESULT_BUSY":         uint64(ResultBusy),
		"FPD_RESULT_TIMEOUT":      uint64(ResultTimeout),
		"FPD_RESULT_DENIED":       uint64(ResultDenied),
		"FPD_RESULT_BAD_REQUEST":  uint64(ResultBadRequest),
		"FPD_RESULT_ERROR":        uint64(ResultError),
		"FPD_RESULT_CANCELLED":    uint64(ResultCancelled),
		"FPD_RESULT_EXISTS":       uint64(ResultExists),
		"FPD_RESULT_REMOTE":       uint64(ResultRemote),
		"FPD_RESULT_LOCKED_OUT":   uint64(ResultLockedOut),
	}
	for name, v := range want {
		if got := num(name); got != v {
			t.Errorf("%s = %d in the header, %d in Go", name, got, v)
		}
	}
	if defs["FPD_SOCKET_PATH"] != strconv.Quote(DefaultSocket) {
		t.Errorf("socket path %s in the header", defs["FPD_SOCKET_PATH"])
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, ReqVerify, U32s(1000, 15000, 3)); err != nil {
		t.Fatal(err)
	}
	if err := Write(&buf, EvPrompt, nil); err != nil {
		t.Fatal(err)
	}
	f, err := Read(&buf)
	if err != nil || f.Type != ReqVerify {
		t.Fatalf("%+v, %v", f, err)
	}
	vals, err := f.Fields(4, 4, 4)
	if err != nil || vals[0] != 1000 || vals[1] != 15000 || vals[2] != 3 {
		t.Fatalf("%v, %v", vals, err)
	}
	if _, err := f.Fields(4, 4); !errors.Is(err, ErrFrame) {
		t.Fatalf("wrong size: %v", err)
	}
	if _, err := f.Fields(3, 3, 3, 3); err == nil {
		t.Fatal("odd field size accepted")
	}
	f, err = Read(&buf)
	if err != nil || f.Type != EvPrompt || len(f.Payload) != 0 {
		t.Fatalf("%+v, %v", f, err)
	}
	if _, err := Read(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("empty: %v", err)
	}
	finger := Frame{Payload: U16(U32s(7), 2)}
	if v, err := finger.Fields(4, 2); err != nil || v[0] != 7 || v[1] != 2 {
		t.Fatalf("u16 field: %v, %v", v, err)
	}

	if err := Write(&buf, 1, make([]byte, MaxPayload+1)); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversized write: %v", err)
	}
	if _, err := Read(bytes.NewReader([]byte{1, 0, 0xff, 0xff})); !errors.Is(err, ErrFrame) {
		t.Fatalf("oversized read: %v", err)
	}
	if _, err := Read(bytes.NewReader([]byte{1, 0, 4, 0, 1})); !errors.Is(err, ErrFrame) {
		t.Fatalf("truncated payload: %v", err)
	}
}

func TestResultString(t *testing.T) {
	if ResultString(ResultBusy) != "sensor busy" || ResultString(99) != "result 99" {
		t.Fatal(ResultString(ResultBusy), ResultString(99))
	}
}
