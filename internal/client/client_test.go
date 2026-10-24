package client

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	"git.airies.net/vifair22/tp-fingerprint/internal/proto"
)

// fake serves one connection with the given frames after reading a request.
func fake(t *testing.T, frames func(c net.Conn)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fpd.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		proto.Read(c)
		frames(c)
		c.Close()
		ln.Close()
	}()
	return path
}

func TestDo(t *testing.T) {
	sock := fake(t, func(c net.Conn) {
		proto.Write(c, proto.EvPrompt, nil)
		proto.Write(c, proto.EvRetry, proto.U32s(proto.RetryScan))
		proto.Write(c, proto.EvProgress, proto.U32s(3))
		proto.Write(c, proto.EvFinger, proto.U16(proto.U32s(1000), 2))
		proto.Write(c, proto.EvResult, proto.U32s(proto.ResultMatch))
	})
	var prompts, retries int
	var touches uint32
	var finger [2]uint32
	err := Do(sock, proto.ReqList, proto.U32s(1000), Events{
		Prompt:   func() { prompts++ },
		Retry:    func(uint32) { retries++ },
		Progress: func(n uint32) { touches = n },
		Finger:   func(u uint32, s uint16) { finger = [2]uint32{u, uint32(s)} },
	})
	if err != nil || prompts != 1 || retries != 1 || touches != 3 || finger != [2]uint32{1000, 2} {
		t.Fatalf("%v: %d %d %d %v", err, prompts, retries, touches, finger)
	}
	// Events with no handler are skipped.
	sock = fake(t, func(c net.Conn) {
		proto.Write(c, proto.EvPrompt, nil)
		proto.Write(c, proto.EvRetry, proto.U32s(1))
		proto.Write(c, proto.EvProgress, proto.U32s(1))
		proto.Write(c, proto.EvFinger, proto.U16(proto.U32s(1), 1))
		proto.Write(c, proto.EvResult, proto.U32s(proto.ResultBusy))
	})
	var re *ResultError
	if err := Do(sock, proto.ReqList, nil, Events{}); !errors.As(err, &re) || re.Code != proto.ResultBusy || re.Error() != "sensor busy" {
		t.Fatalf("busy: %v", err)
	}
}

func TestDoErrors(t *testing.T) {
	if err := Do(filepath.Join(t.TempDir(), "none"), proto.ReqList, nil, Events{}); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("no socket: %v", err)
	}
	for name, frames := range map[string]func(net.Conn){
		"hang up":       func(net.Conn) {},
		"bad result":    func(c net.Conn) { proto.Write(c, proto.EvResult, nil) },
		"bad retry":     func(c net.Conn) { proto.Write(c, proto.EvRetry, nil) },
		"bad finger":    func(c net.Conn) { proto.Write(c, proto.EvFinger, proto.U32s(1)) },
		"unknown frame": func(c net.Conn) { proto.Write(c, 0x99, nil) },
	} {
		if err := Do(fake(t, frames), proto.ReqList, nil, Events{}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := Do(fake(t, func(net.Conn) {}), proto.ReqList, make([]byte, proto.MaxPayload+1), Events{}); err == nil {
		t.Error("oversized request sent")
	}
}
