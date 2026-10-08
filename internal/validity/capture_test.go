package validity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// simScan is the simulated sensor's enrollment and matching state.
type simScan struct {
	// scanErrors queues the error word of successive capture results
	// (0 is a good scan).
	scanErrors []uint32
	// need is how many images complete an enrollment.
	need     int
	images   int
	key      uint32
	updates  int
	template []byte
	// match is the user record id the next match reports; 0 is no match.
	match   uint16
	subtype uint16
}

// goodTouch is the interrupt sequence of a clean capture: start, a few
// idle reports, finger down, two updates, the last with the done bit.
func goodTouch() [][]byte {
	return [][]byte{{0, 0, 0}, {1, 0, 0}, {2, 0, 0}, {3, 0, 1}, {3, 0, 4}}
}

func (s *simSensor) scanCmd(req []byte) []byte {
	ok := []byte{0, 0}
	sc := &s.scan
	switch req[0] {
	case 0x51:
		code := uint32(0)
		if len(sc.scanErrors) > 0 {
			code, sc.scanErrors = sc.scanErrors[0], sc.scanErrors[1:]
		}
		res := concat(u16s(10, 20, 30, 40), binary.LittleEndian.AppendUint32(nil, code))
		return concat(ok, binary.LittleEndian.AppendUint32(nil, uint32(len(res))), res)
	case 0x68:
		if got := binary.LittleEndian.Uint32(req[1:]); got != sc.key {
			s.t.Errorf("sim: enrollment key %d, want %d", got, sc.key)
		}
		sc.key += 0x10
		s.tls.ints = append(s.tls.ints, []byte{5, 0, 0})
		return concat(ok, binary.LittleEndian.AppendUint32(nil, sc.key))
	case 0x6b:
		if !bytes.Equal(req[1:], sc.template) {
			s.t.Errorf("sim: enrollment update with %d-byte template, want the last one (%d bytes)", len(req)-1, len(sc.template))
		}
		sc.updates++
		if sc.updates%2 == 1 {
			s.tls.ints = append(s.tls.ints, []byte{6, 0, 0})
			return ok
		}
		sc.images++
		block := func(tag int, body []byte) []byte {
			return concat(u16s(tag, len(body)), make([]byte, enrollMagicLen-4), body)
		}
		sc.template = block(0, bytes.Repeat([]byte{byte(sc.images)}, 40))
		body := concat(block(1, []byte{byte(sc.images)}), sc.template)
		if sc.images >= sc.need {
			body = concat(body, block(3, []byte("template-id")))
		}
		return concat(ok, u16s(len(body)), body)
	case 0x5e:
		if !bytes.Equal(req, mustHex("5e02ff00000000010000000000")) {
			s.t.Errorf("sim: match request %x", req)
		}
		if sc.match == 0 {
			s.tls.ints = append(s.tls.ints, []byte{4, 0, 0})
		} else {
			s.tls.ints = append(s.tls.ints, []byte{3, 0, 0})
		}
		return ok
	case 0x60:
		field := func(t int, v []byte) []byte { return concat(u16s(t, len(v)), v) }
		body := concat(field(1, binary.LittleEndian.AppendUint32(nil, uint32(sc.match))),
			field(3, u16s(int(sc.subtype))), field(4, []byte("hash")))
		return concat(ok, u16s(len(body)), body)
	}
	return []byte{1, 0}
}

// scanningSim is a paired, calibrated simulated sensor ready to scan.
func scanningSim(t *testing.T) (*simSensor, *Sensor) {
	t.Helper()
	s, sess := calibratedSim(t)
	sen, err := OpenSensor(sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sen.Calibrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	s.frames = nil
	s.touch = goodTouch
	s.scan.need = 4
	return s, sen
}

func TestEnrollThenIdentify(t *testing.T) {
	ctx := context.Background()
	s, sen := scanningSim(t)
	// Two rejected touches along the way.
	s.scan.scanErrors = []uint32{0, 0x0b, 0, 0x0b, 0}
	var events []EnrollEvent
	sid := UIDSID(1000)
	s.tls.ints = nil
	fid, tid, err := sen.Enroll(ctx, sid, 2, func(e EnrollEvent) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	if string(tid) != "template-id" {
		t.Fatalf("tid %q", tid)
	}
	var good, bad int
	for _, e := range events {
		if e.Err == nil {
			good++
		} else if errors.Is(e.Err, ErrScan) {
			bad++
		}
	}
	if good != 4 || bad != 2 || events[len(events)-1].Touch != 4 {
		t.Fatalf("events %+v", events)
	}

	db := NewDB(sen.sess)
	stg, _ := db.Storage()
	u, err := db.LookupUser(stg.ID, sid)
	if err != nil || u == nil || len(u.Fingers) != 1 || u.Fingers[0].ID != fid || u.Fingers[0].Subtype != 2 {
		t.Fatalf("user after enrollment %+v, %v", u, err)
	}
	rec, _ := db.RecordValue(fid)
	if !bytes.Equal(rec.Value, fingerData(2, s.scan.template, []byte("template-id"))) {
		t.Fatal("finger record does not hold the final template and id")
	}
	// A second finger joins the same user record.
	s.scan = simScan{need: 2}
	if _, _, err := sen.Enroll(ctx, sid, 7, nil); err != nil {
		t.Fatal(err)
	}
	if u, _ := db.LookupUser(stg.ID, sid); len(u.Fingers) != 2 {
		t.Fatalf("second finger: %+v", u)
	}

	s.scan.match, s.scan.subtype = u.ID, 2
	m, err := sen.Identify(ctx, nil)
	if err != nil || m.User != u.ID || m.Subtype != 2 || string(m.Hash) != "hash" {
		t.Fatalf("identify %+v, %v", m, err)
	}
	log := strings.Join(s.cmds, " ")
	// Cleaned up before the match as well as after.
	if !strings.Contains(log, "tls:62 tls:5e tls:60 tls:62") {
		t.Fatalf("match sequence missing from %s", log[len(log)-200:])
	}
	s.scan.match = 0
	if _, err := sen.Identify(ctx, nil); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("unknown finger: %v", err)
	}
}

func TestEnrollGivesUp(t *testing.T) {
	sim, sen := scanningSim(t)
	for range maxEnrollFailures {
		sim.scan.scanErrors = append(sim.scan.scanErrors, 0x0b)
	}
	_, _, err := sen.Enroll(context.Background(), UIDSID(1), 1, nil)
	if !errors.Is(err, ErrEnrollAborted) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollStopsOnFatalErrors(t *testing.T) {
	t.Run("unexpected first interrupt", func(t *testing.T) {
		s, sen := scanningSim(t)
		s.touch = func() [][]byte { return [][]byte{{3, 0, 0}} }
		if _, _, err := sen.Enroll(context.Background(), UIDSID(1), 1, nil); err == nil || errors.Is(err, ErrEnrollAborted) {
			t.Fatalf("err = %v, want an immediate failure", err)
		}
	})
	t.Run("finger never arrives", func(t *testing.T) {
		s, sen := scanningSim(t)
		s.touch = func() [][]byte { return [][]byte{{0, 0, 0}} }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := sen.Enroll(ctx, UIDSID(1), 1, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("malformed update reply", func(t *testing.T) {
		s, sen := scanningSim(t)
		orig := s.tls.reply
		s.tls.reply = func(req []byte) []byte {
			if req[0] == 0x6b && s.scan.updates%2 == 1 {
				s.scan.updates++
				return []byte{0, 0, 9, 0}
			}
			return orig(req)
		}
		if _, _, err := sen.Enroll(context.Background(), UIDSID(1), 1, nil); !errors.Is(err, ErrShortReply) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("storage cannot be created", func(t *testing.T) {
		s, sen := scanningSim(t)
		s.fail = "tls:47"
		if _, _, err := sen.Enroll(context.Background(), UIDSID(1), 1, nil); err == nil {
			t.Fatal("enrolled")
		}
	})
}

func TestIdentifyRetriesAndCancels(t *testing.T) {
	identifyRetryDelay = 0
	defer func() { identifyRetryDelay = 1e9 }()
	s, sen := scanningSim(t)
	s.scan.scanErrors = []uint32{0x0b, 0x0b}
	s.scan.match, s.scan.subtype = 9, 1
	var retries int
	m, err := sen.Identify(context.Background(), func(error) { retries++ })
	if err != nil || retries != 2 || m.User != 9 {
		t.Fatalf("%+v, %d retries, %v", m, retries, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sen.Identify(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled identify: %v", err)
	}
	s.fail = "tls:39"
	if _, err := sen.Identify(context.Background(), nil); err == nil {
		t.Fatal("identified with the LED refusing")
	}
}

func TestMatchReplyErrors(t *testing.T) {
	tests := []string{
		"0000 0100",                // length mismatch
		"0000 0400 0100 0800",      // field overrun
		"0000 0600 0300 0200 0100", // no user field
		"0000 0300 01",             // truncated field header
	}
	for _, rsp := range tests {
		s, sen := scanningSim(t)
		s.scan.match = 1
		bad := unhex(t, rsp)
		orig := s.tls.reply
		s.tls.reply = func(req []byte) []byte {
			if req[0] == 0x60 {
				return bad
			}
			return orig(req)
		}
		s.tls.ints = [][]byte{{3, 0, 0}}
		if _, err := sen.match(context.Background()); err == nil {
			t.Errorf("%s: matched", rsp)
		}
	}
}

func TestFingerData(t *testing.T) {
	got := fingerData(2, []byte{0xaa}, []byte{0xbb, 0xcc})
	want := "0200" + "0300" + "0b00" + "2000" + "0100" + "0100" + "aa" + "0200" + "0200" + "bbcc" + strings.Repeat("00", 0x20)
	if hexOf(got) != want {
		t.Fatalf("got %s", hexOf(got))
	}
}

func TestParseFingerData(t *testing.T) {
	v := fingerData(7, bytes.Repeat([]byte{0xaa}, 100), []byte("the-tid"))
	sub, tid, err := ParseFingerData(v)
	if err != nil || sub != 7 || string(tid) != "the-tid" {
		t.Fatalf("%d %q %v", sub, tid, err)
	}
	for name, bad := range map[string][]byte{
		"short":            v[:10],
		"wrong tag":        append(u16s(7, 3, 0, 0x20, 9, 0), v[12:]...),
		"template overrun": append(u16s(7, 3, 0, 0x20, 1, 5000), v[12:]...),
		"tid overrun":      v[:len(v)-0x20-3],
	} {
		if _, _, err := ParseFingerData(bad); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
