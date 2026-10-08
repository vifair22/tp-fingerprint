package validity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"testing"
	"time"
)

// tlsSensor is the sensor's half of the handshake, written from the
// protocol description in session.go rather than from the client code,
// so the two check each other. It shares only the primitives (prf, CBC,
// padding), which crypto_test.go pins to the reference.
type tlsSensor struct {
	t *testing.T
	f *pairingFixture

	hs                         hash.Hash
	clientRandom, serverRandom []byte
	master                     []byte
	// Keys named from the host's side, as session.go names them.
	signKey, validationKey, encKey, decKey []byte

	pending []byte
	flights int

	suite uint16
	// hostPub checks CertificateVerify; pairing replaces it with the key
	// the host certified.
	hostPub *ecdsa.PublicKey
	// plain answers commands outside the session; nil treats every
	// non-handshake command as application data.
	plain func(req []byte) []byte
	// reply answers a decrypted command; nil echoes it after a 0000
	// status.
	reply func(req []byte) []byte
	// badFinished makes the sensor's Finished seal correctly but carry
	// the wrong verify data.
	badFinished bool
	// mutate rewrites a response before the host reads it.
	mutate func(flight int, rsp []byte) []byte
}

func newTLSSensor(t *testing.T) *tlsSensor {
	f := newPairingFixture(t)
	return &tlsSensor{t: t, f: f, hs: sha256.New(), suite: suiteECDHECDSAAES256, hostPub: &f.host.PublicKey}
}

// endSession forgets the session, as a sensor reboot does.
func (s *tlsSensor) endSession() {
	s.hs = sha256.New()
	s.clientRandom, s.serverRandom, s.master = nil, nil, nil
}

func (s *tlsSensor) pairing(t *testing.T) *Pairing {
	t.Helper()
	p, err := ParseTLSFlash(s.f.flash(t), s.f.keys, &s.f.fw.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *tlsSensor) Bulk(ep uint8, buf []byte, _ time.Duration) (int, error) {
	if ep == epCmdIn {
		return copy(buf, s.pending), nil
	}
	s.flights++
	var rsp []byte
	switch {
	case bytes.HasPrefix(buf, handshakePrefix) && s.serverRandom == nil:
		rsp = s.firstFlight(buf[4:])
	case bytes.HasPrefix(buf, handshakePrefix):
		rsp = s.secondFlight(buf[4:])
	case s.plain != nil && (s.master == nil || buf[0] != recAppData):
		rsp = s.plain(buf)
	default:
		rsp = s.appData(buf)
	}
	if s.mutate != nil {
		rsp = s.mutate(s.flights, rsp)
	}
	s.pending = rsp
	return len(buf), nil
}

type record struct {
	t    byte
	body []byte
}

func (s *tlsSensor) records(b []byte) []record {
	s.t.Helper()
	var out []record
	for len(b) > 0 {
		if len(b) < 5 || b[1] != 3 || b[2] != 3 {
			s.t.Fatalf("sensor: bad record header %x", b)
		}
		n := int(binary.BigEndian.Uint16(b[3:]))
		out = append(out, record{b[0], b[5 : 5+n]})
		b = b[5+n:]
	}
	return out
}

// messages splits handshake messages, returning each with its header.
func (s *tlsSensor) messages(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		n := 4 + (int(b[1])<<16 | int(b[2])<<8 | int(b[3]))
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

func (s *tlsSensor) firstFlight(b []byte) []byte {
	recs := s.records(b)
	if len(recs) != 1 || recs[0].t != recHandshake {
		s.t.Fatalf("sensor: first flight %v", recs)
	}
	hello := recs[0].body
	if hello[0] != hsClientHello || hello[4] != 3 || hello[5] != 3 {
		s.t.Fatalf("sensor: not a ClientHello: %x", hello)
	}
	s.hs.Write(hello)
	s.clientRandom = hello[6:38]
	s.serverRandom = bytes.Repeat([]byte{0x5e}, 32)

	sh := concat([]byte{3, 3}, s.serverRandom, []byte{0}, u16(int(s.suite)), []byte{0})
	msgs := concat(
		[]byte{hsServerHello}, u24(len(sh)), sh,
		[]byte{hsCertRequest, 0, 0, 4, 0x01, 0x40, 0, 0},
		[]byte{hsServerHelloDone, 0, 0, 0},
	)
	s.hs.Write(msgs)
	return concat([]byte{recHandshake, 3, 3}, u16(len(msgs)), msgs)
}

func (s *tlsSensor) secondFlight(b []byte) []byte {
	recs := s.records(b)
	if len(recs) != 3 || recs[0].t != recHandshake || recs[1].t != recChangeCipherSpec ||
		!bytes.Equal(recs[1].body, []byte{1}) || recs[2].t != recHandshake {
		s.t.Fatalf("sensor: second flight shape %v", recs)
	}
	for _, m := range s.messages(recs[0].body) {
		body := m[4:]
		switch m[0] {
		case hsCertificate:
			c := s.f.cert
			want := concat([]byte{0}, u16(len(c)), []byte{0}, u16(len(c)), []byte{0xac, 0x16}, c)
			if !bytes.Equal(body, want) {
				s.t.Errorf("sensor: Certificate body %x", body[:16])
			}
		case hsClientKeyExchange:
			pub, err := ecdh.P256().NewPublicKey(body)
			if err != nil {
				s.t.Fatalf("sensor: ClientKeyExchange point: %v", err)
			}
			pre, err := s.f.sensor.ECDH(pub)
			if err != nil {
				s.t.Fatal(err)
			}
			seed := concat(s.clientRandom, s.serverRandom)
			s.master = prf(pre, concat([]byte("master secret"), seed), 0x30)
			kb := prf(s.master, concat([]byte("key expansion"), seed), 0x120)
			s.signKey, s.validationKey, s.encKey, s.decKey = kb[0:32], kb[32:64], kb[64:96], kb[96:128]
		case hsCertVerify:
			if !ecdsa.VerifyASN1(s.hostPub, s.hs.Sum(nil), body) {
				s.t.Error("sensor: CertificateVerify does not verify")
			}
		default:
			s.t.Fatalf("sensor: unexpected message 0x%02x", m[0])
		}
		s.hs.Write(m)
	}
	fin := s.unseal(recHandshake, recs[2].body)
	want := concat([]byte{hsFinished, 0, 0, 12}, prf(s.master, concat([]byte("client finished"), s.hs.Sum(nil)), 12))
	if !bytes.Equal(fin, want) {
		s.t.Error("sensor: client Finished does not verify")
	}
	label := "server finished"
	if s.badFinished {
		label = "client finished"
	}
	sfin := concat([]byte{hsFinished, 0, 0, 12}, prf(s.master, concat([]byte(label), s.hs.Sum(nil)), 12))
	return concat([]byte{recChangeCipherSpec, 3, 3, 0, 1, 1}, s.seal(recHandshake, sfin))
}

func (s *tlsSensor) appData(b []byte) []byte {
	recs := s.records(b)
	if len(recs) != 1 || recs[0].t != recAppData {
		s.t.Fatalf("sensor: command records %v", recs)
	}
	req := s.unseal(recAppData, recs[0].body)
	var rsp []byte
	if s.reply != nil {
		rsp = s.reply(req)
	} else {
		rsp = concat([]byte{0, 0}, req)
	}
	return s.seal(recAppData, rsp)
}

func (s *tlsSensor) unseal(t byte, b []byte) []byte {
	s.t.Helper()
	m, err := cbcDecrypt(s.encKey, b)
	if err != nil {
		s.t.Fatal(err)
	}
	if m, err = tlsUnpad(m); err != nil {
		s.t.Fatal(err)
	}
	body, mac := m[:len(m)-32], m[len(m)-32:]
	if !hmac.Equal(mac, hmacSHA256(s.signKey, recordHeader(t, len(body)), body)) {
		s.t.Fatal("sensor: host record MAC does not verify")
	}
	return body
}

func (s *tlsSensor) seal(t byte, body []byte) []byte {
	s.t.Helper()
	mac := hmacSHA256(s.validationKey, recordHeader(t, len(body)), body)
	c, err := cbcEncrypt(s.decKey, tlsPad(concat(body, mac)))
	if err != nil {
		s.t.Fatal(err)
	}
	return concat([]byte{t, 3, 3}, u16(len(c)), c)
}

func TestSessionHandshakeAndCommands(t *testing.T) {
	s := newTLSSensor(t)
	busy := 2
	s.reply = func(req []byte) []byte {
		if req[0] == 0x75 && busy > 0 {
			busy--
			return []byte{0x04, 0x01}
		}
		return concat([]byte{0, 0}, req)
	}
	link, slept := newTestLink(&fakeSensor{t: t})
	link.t = s
	sess, err := OpenSession(link, s.pairing(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range [][]byte{{0x01}, bytes.Repeat([]byte{0x3e}, 300), {0x75}} {
		got, err := sess.CmdOK(req)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, req) {
			t.Fatalf("payload %x, want %x", got, req)
		}
	}
	if len(*slept) != 2 {
		t.Fatalf("busy retries inside the session: %d, want 2", len(*slept))
	}
	// The command helpers run over the session as they do over the link.
	if _, err := GetRomInfo(sess); !errors.Is(err, ErrShortReply) {
		t.Fatalf("GetRomInfo over the session: %v", err)
	}
	if _, err := sess.Raw(nil); err == nil {
		t.Fatal("empty command accepted")
	}
}

func TestSessionFailures(t *testing.T) {
	// flip changes one byte of a sealed record's IV, which alters the
	// first plaintext block predictably, so the MAC check (not the
	// padding check) is what catches it.
	flip := func(flight, at int) func(int, []byte) []byte {
		return func(f int, rsp []byte) []byte {
			if f == flight {
				rsp = append([]byte(nil), rsp...)
				rsp[at] ^= 1
			}
			return rsp
		}
	}
	tests := []struct {
		name   string
		setup  func(s *tlsSensor)
		cmd    bool // the failure is in a command, not the handshake
		errMsg string
	}{
		{name: "unsupported suite", setup: func(s *tlsSensor) { s.suite = 0x003d }, errMsg: "cipher suite 0x003d"},
		{
			name: "no ServerHello",
			setup: func(s *tlsSensor) {
				s.mutate = func(f int, rsp []byte) []byte {
					if f == 1 {
						return []byte{recHandshake, 3, 3, 0, 4, hsServerHelloDone, 0, 0, 0}
					}
					return rsp
				}
			},
			errMsg: "no ServerHello",
		},
		{
			name: "no ChangeCipherSpec from the sensor",
			setup: func(s *tlsSensor) {
				s.mutate = func(f int, rsp []byte) []byte {
					if f == 2 {
						return nil
					}
					return rsp
				}
			},
			errMsg: "did not switch",
		},
		{name: "sensor Finished wrong", setup: func(s *tlsSensor) { s.badFinished = true }, errMsg: "Finished does not verify"},
		{name: "sensor Finished corrupted", setup: func(s *tlsSensor) { s.mutate = flip(2, 6+5) }, errMsg: "MAC does not verify"},
		{name: "command reply corrupted", setup: func(s *tlsSensor) { s.mutate = flip(3, 5) }, cmd: true, errMsg: "reply to 0x01"},
		{
			name: "plaintext record after the switch",
			setup: func(s *tlsSensor) {
				s.mutate = func(f int, rsp []byte) []byte {
					if f == 3 {
						return []byte{recHandshake, 3, 3, 0, 4, 0x99, 0, 0, 0}
					}
					return rsp
				}
			},
			cmd:    true,
			errMsg: "malformed cbc payload",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTLSSensor(t)
			tt.setup(s)
			link := NewLink(s, nil)
			sess, err := OpenSession(link, s.pairing(t))
			if tt.cmd {
				if err != nil {
					t.Fatal(err)
				}
				_, _, err = sess.Cmd([]byte{0x01})
			} else if !errors.Is(err, ErrHandshake) {
				t.Fatalf("err = %v, want ErrHandshake", err)
			}
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("err = %v, want %q", err, tt.errMsg)
			}
		})
	}
}

func TestSessionTransportErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, flight := range []int{1, 2, 3} {
		s := newTLSSensor(t)
		ft := &failingTransport{inner: s, failAt: flight, err: boom}
		sess, err := OpenSession(NewLink(ft, nil), s.pairing(t))
		if flight == 3 {
			if err != nil {
				t.Fatal(err)
			}
			_, err = sess.Raw([]byte{1})
		}
		if !errors.Is(err, boom) {
			t.Errorf("flight %d: err = %v", flight, err)
		}
	}
}

type failingTransport struct {
	inner  Transport
	failAt int
	writes int
	err    error
}

func (f *failingTransport) Bulk(ep uint8, buf []byte, d time.Duration) (int, error) {
	if ep == epCmdOut {
		f.writes++
		if f.writes == f.failAt {
			return 0, f.err
		}
	}
	return f.inner.Bulk(ep, buf, d)
}

// Record and message parsing on a session with no keys yet, for the
// branches a well-behaved peer never reaches.
func TestParseRecordsRejects(t *testing.T) {
	sh := func(body string) string {
		b := unhex(t, body)
		return "160303" + hexU16(4+len(b)) + "02" + hexU24(len(b)) + body
	}
	tests := []struct {
		name string
		in   string
		want string // "" means no error
	}{
		{"short tail is zero-padded", "160303", ""},
		{"short tail with a bad version", "1603", "record version 3.0"},
		{"record version", "160301000100", "record version 3.1"},
		{"unknown record type", "150303000100", "record type 0x15"},
		{"app data before the session", "170303000100", "before the session"},
		{"ccs payload", "140303000102", "ChangeCipherSpec payload"},
		{"ccs before keys", "140303000101", "before key exchange"},
		{"unknown handshake message", "16030300049900" + "0000", "handshake message 0x99"},
		{"short handshake tail is zero-padded", "1603030002" + "0e00", ""},
		{"hello done with a body", "16030300050e00000100", "ServerHelloDone with"},
		{"finished before keys", "16030300041400000c", "before key exchange"},
		{"cert request length", "16030300050d00000100", "CertificateRequest: 1 bytes"},
		{"cert request algorithm", "16030300080d0000040203" + "0000", "signature algorithm 0x0203"},
		{"cert request CAs", "16030300080d0000040140" + "0001", "non-empty CA list"},
		{"server hello version", sh("0302" + strings.Repeat("00", 36)), "bad version"},
		{"server hello trailing", sh("0303" + strings.Repeat("00", 32) + "00" + "c00500" + "ff"), "after the random"},
		{"server hello compression", sh("0303" + strings.Repeat("00", 32) + "00" + "c00501"), "compression method 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{hs: sha256.New()}
			_, err := s.parseRecords(unhex(t, tt.in))
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestOpenRecordRejects(t *testing.T) {
	s := &Session{decKey: make([]byte, 32), validationKey: make([]byte, 32)}
	short, _ := cbcEncrypt(s.decKey, tlsPad(make([]byte, 10)))
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"not whole blocks", make([]byte, 20)},
		{"shorter than a MAC", short},
	}
	for _, tt := range tests {
		if _, err := s.open(recAppData, tt.pkt); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
	// Padding that claims more bytes than the record holds.
	bad, _ := cbcEncrypt(s.decKey, bytes.Repeat([]byte{0xff}, 16))
	if _, err := s.open(recAppData, bad); !errors.Is(err, errCBC) {
		t.Errorf("bad padding: %v", err)
	}
}

func TestSealBeforeSession(t *testing.T) {
	if _, err := (&Session{}).seal(recAppData, []byte{1}); err == nil {
		t.Fatal("sealed without keys")
	}
}

func hexU16(n int) string { return hex.EncodeToString(u16(n)) }
func hexU24(n int) string { return hex.EncodeToString(u24(n)) }
