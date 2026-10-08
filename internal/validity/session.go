package validity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

// The sensor speaks a cut-down TLS 1.2 with one cipher suite,
// TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005), but with HMAC-SHA256 and
// 32-byte MAC keys, wrapped in USB commands. It is close enough to TLS to
// read the RFC alongside, and far enough that crypto/tls cannot speak it,
// so it is ported from the reference byte for byte, quirks included; each
// quirk is marked where it occurs.
//
// Handshake (one USB exchange per flight, each request prefixed 44000000):
//
//	host:   ClientHello
//	sensor: ServerHello, CertificateRequest, ServerHelloDone
//	host:   Certificate, ClientKeyExchange, CertificateVerify,
//	        ChangeCipherSpec, Finished (encrypted)
//	sensor: ChangeCipherSpec, Finished (encrypted)
//
// After that every command is one application-data record and so is
// every reply.

const (
	recChangeCipherSpec = 0x14
	recHandshake        = 0x16
	recAppData          = 0x17

	hsClientHello       = 0x01
	hsServerHello       = 0x02
	hsCertificate       = 0x0b
	hsCertRequest       = 0x0d
	hsServerHelloDone   = 0x0e
	hsCertVerify        = 0x0f
	hsClientKeyExchange = 0x10
	hsFinished          = 0x14

	suiteECDHECDSAAES256 = 0xc005
	// The only signature algorithm the sensor asks for: ECDSA with
	// SHA-256 as the reference reads it (0x01 0x40 on the wire).
	certReqSigAlg = 0x0140
)

var handshakePrefix = []byte{0x44, 0x00, 0x00, 0x00}

// ErrHandshake wraps every way the handshake can fail.
var ErrHandshake = errors.New("tls handshake failed")

// Session is an established TLS session. Like Link it has one owner.
type Session struct {
	link *Link
	pair *Pairing

	hs                         hash.Hash // running handshake transcript
	clientRandom, serverRandom []byte
	master                     []byte
	signKey, validationKey     []byte // our MAC key, the sensor's
	encKey, decKey             []byte
	secureRx, secureTx         bool
}

// OpenSession runs the handshake over link using the pairing read from
// the sensor's flash.
func OpenSession(link *Link, pair *Pairing) (*Session, error) {
	s := &Session{link: link, pair: pair, hs: sha256.New()}
	if err := s.handshake(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return s, nil
}

func (s *Session) handshake() error {
	hello := s.clientHello()
	rsp, err := s.link.Raw(concat(handshakePrefix, s.handshakeRecord(hello)))
	if err != nil {
		return err
	}
	if _, err := s.parseRecords(rsp); err != nil {
		return err
	}
	if s.serverRandom == nil {
		return errors.New("no ServerHello in the sensor's first flight")
	}
	eph, err := s.deriveKeys()
	if err != nil {
		return err
	}

	// Argument order matters: Certificate, ClientKeyExchange and
	// CertificateVerify join the transcript as they are built, and the
	// signature covers the first two.
	flight := s.certificate()
	flight = append(flight, s.clientKeyExchange(eph)...)
	cv, err := s.certVerify()
	if err != nil {
		return err
	}
	flight = append(flight, cv...)
	req := concat(handshakePrefix, s.handshakeRecord(flight))
	req = append(req, recChangeCipherSpec, 3, 3, 0, 1, 1)
	// Quirk: the client Finished is not added to the transcript, so the
	// sensor's Finished covers everything up to CertificateVerify.
	s.secureTx = true
	req = append(req, s.handshakeRecord(s.finished())...)

	if rsp, err = s.link.Raw(req); err != nil {
		return err
	}
	if _, err := s.parseRecords(rsp); err != nil {
		return err
	}
	if !s.secureRx {
		return errors.New("sensor did not switch to the encrypted channel")
	}
	return nil
}

// Raw sends req as one application-data record and returns the decrypted
// reply, status word included.
func (s *Session) Raw(req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, errors.New("empty command")
	}
	s.link.log.Debug("tls >", "data", hex.EncodeToString(req))
	rec, err := s.seal(recAppData, req)
	if err != nil {
		return nil, err
	}
	rsp, err := s.link.Raw(rec)
	if err != nil {
		return nil, err
	}
	app, err := s.parseRecords(rsp)
	if err != nil {
		return nil, fmt.Errorf("reply to 0x%02x: %w", req[0], err)
	}
	s.link.log.Debug("tls <", "data", hex.EncodeToString(app))
	return app, nil
}

// Cmd is Link.Cmd inside the session.
func (s *Session) Cmd(req []byte) (Status, []byte, error) { return s.link.retryBusy(s, req) }

// CmdOK is Link.CmdOK inside the session.
func (s *Session) CmdOK(req []byte) ([]byte, error) { return cmdOK(s, req) }

// --- outgoing messages ---

// handshakeMsg frames a handshake message and adds it to the transcript.
func (s *Session) handshakeMsg(t byte, body []byte) []byte {
	m := append([]byte{t}, u24(len(body))...)
	m = append(m, body...)
	s.hs.Write(m)
	return m
}

func (s *Session) clientHello() []byte {
	s.clientRandom = make([]byte, 32)
	rand.Read(s.clientRandom)
	h := []byte{3, 3}
	h = append(h, s.clientRandom...)
	h = append(h, 7, 0, 0, 0, 0, 0, 0, 0) // session id: seven zero bytes
	// The reference offers 0xc005 and two RSA suites the sensor never
	// picks; they are kept so the hello is byte-identical.
	h = append(h, 0, 6, 0xc0, 0x05, 0x00, 0x3d, 0x00, 0x8d)
	h = append(h, 0) // no compression methods
	exts := []byte{
		0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // truncated_hmac, "0x17"
		0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats: uncompressed
	}
	// Quirk: the extensions length is two short. The sensor expects it.
	h = append(h, u16(len(exts)-2)...)
	h = append(h, exts...)
	return s.handshakeMsg(hsClientHello, h)
}

func (s *Session) certificate() []byte {
	cert := s.pair.Cert
	// Quirk: both length fields carry the bare certificate's length
	// rather than the length of what follows them, and the two bytes
	// ac16 are of unknown meaning.
	b := []byte{0}
	b = append(b, u16(len(cert))...)
	b = append(b, 0)
	b = append(b, u16(len(cert))...)
	b = append(b, 0xac, 0x16)
	b = append(b, cert...)
	return s.handshakeMsg(hsCertificate, b)
}

func (s *Session) clientKeyExchange(eph *ecdh.PrivateKey) []byte {
	// Uncompressed point, fixed 32-byte coordinates. The reference strips
	// leading zero bytes from each coordinate, which would produce a
	// malformed point for about 1 in 128 handshakes; this does not.
	return s.handshakeMsg(hsClientKeyExchange, eph.PublicKey().Bytes())
}

func (s *Session) certVerify() ([]byte, error) {
	digest := s.hs.Sum(nil)
	sig, err := ecdsa.SignASN1(rand.Reader, s.pair.HostKey, digest)
	if err != nil {
		return nil, err
	}
	return s.handshakeMsg(hsCertVerify, sig), nil
}

func (s *Session) finished() []byte {
	verify := prf(s.master, concat([]byte("client finished"), s.hs.Sum(nil)), 12)
	return concat([]byte{hsFinished}, u24(len(verify)), verify)
}

// handshakeRecord wraps handshake messages in one record, sealed once the
// host has switched to the encrypted channel.
func (s *Session) handshakeRecord(msgs []byte) []byte {
	if s.secureTx {
		rec, err := s.seal(recHandshake, msgs)
		if err != nil {
			// Keys are fixed-size and set before secureTx; AES cannot
			// reject them.
			panic(err)
		}
		return rec
	}
	return concat([]byte{recHandshake, 3, 3}, u16(len(msgs)), msgs)
}

func (s *Session) deriveKeys() (*ecdh.PrivateKey, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pre, err := eph.ECDH(s.pair.SensorKey)
	if err != nil {
		return nil, err
	}
	seed := concat(s.clientRandom, s.serverRandom)
	s.master = prf(pre, concat([]byte("master secret"), seed), 0x30)
	kb := prf(s.master, concat([]byte("key expansion"), seed), 0x120)
	s.signKey, s.validationKey = kb[0x00:0x20], kb[0x20:0x40]
	s.encKey, s.decKey = kb[0x40:0x60], kb[0x60:0x80]
	return eph, nil
}

// seal MACs then encrypts one record body and frames it.
func (s *Session) seal(t byte, body []byte) ([]byte, error) {
	if !s.secureTx {
		return nil, errors.New("encrypted record before the session is up")
	}
	mac := hmacSHA256(s.signKey, recordHeader(t, len(body)), body)
	c, err := cbcEncrypt(s.encKey, tlsPad(concat(body, mac)))
	if err != nil {
		return nil, err
	}
	return concat([]byte{t, 3, 3}, u16(len(c)), c), nil
}

// --- incoming records ---

// parseRecords handles every record in rsp and returns the concatenated
// application data.
func (s *Session) parseRecords(rsp []byte) ([]byte, error) {
	var app []byte
	for len(rsp) > 0 {
		// Quirk kept from the reference: a short tail is zero-padded to a
		// full header rather than rejected.
		if len(rsp) < 5 {
			rsp = append(append([]byte(nil), rsp...), make([]byte, 5-len(rsp))...)
		}
		t, major, minor := rsp[0], rsp[1], rsp[2]
		size := int(binary.BigEndian.Uint16(rsp[3:]))
		rsp = rsp[5:]
		size = min(size, len(rsp))
		pkt := rsp[:size]
		rsp = rsp[size:]
		if major != 3 || minor != 3 {
			return nil, fmt.Errorf("record version %d.%d", major, minor)
		}
		switch t {
		case recHandshake:
			if err := s.handleHandshake(pkt); err != nil {
				return nil, err
			}
		case recChangeCipherSpec:
			if !bytes.Equal(pkt, []byte{1}) {
				return nil, fmt.Errorf("ChangeCipherSpec payload %x", pkt)
			}
			if s.decKey == nil {
				return nil, errors.New("ChangeCipherSpec before key exchange")
			}
			s.secureRx = true
		case recAppData:
			if !s.secureRx {
				return nil, errors.New("application data before the session is up")
			}
			b, err := s.open(recAppData, pkt)
			if err != nil {
				return nil, err
			}
			app = append(app, b...)
		default:
			return nil, fmt.Errorf("record type 0x%02x", t)
		}
	}
	return app, nil
}

// open decrypts and authenticates one record body.
func (s *Session) open(t byte, pkt []byte) ([]byte, error) {
	m, err := cbcDecrypt(s.decKey, pkt)
	if err != nil {
		return nil, err
	}
	if m, err = tlsUnpad(m); err != nil {
		return nil, err
	}
	if len(m) < sha256.Size {
		return nil, fmt.Errorf("record of %d bytes: %w", len(m), ErrShortReply)
	}
	body, mac := m[:len(m)-sha256.Size], m[len(m)-sha256.Size:]
	if !hmac.Equal(mac, hmacSHA256(s.validationKey, recordHeader(t, len(body)), body)) {
		return nil, errors.New("record MAC does not verify")
	}
	return body, nil
}

func (s *Session) handleHandshake(b []byte) error {
	if s.secureRx {
		var err error
		if b, err = s.open(recHandshake, b); err != nil {
			return err
		}
	}
	for len(b) > 0 {
		// Same zero-padding quirk as for record headers.
		if len(b) < 4 {
			b = append(append([]byte(nil), b...), make([]byte, 4-len(b))...)
		}
		hdr := b[:4]
		size := min(int(hdr[1])<<16|int(hdr[2])<<8|int(hdr[3]), len(b)-4)
		p := b[4 : 4+size]
		b = b[4+size:]
		var err error
		switch hdr[0] {
		case hsServerHello:
			err = s.serverHello(p)
		case hsCertRequest:
			err = certRequest(p)
		case hsServerHelloDone:
			if len(p) != 0 {
				err = fmt.Errorf("ServerHelloDone with a %d-byte body", len(p))
			}
		case hsFinished:
			err = s.serverFinished(p)
		default:
			err = fmt.Errorf("handshake message 0x%02x", hdr[0])
		}
		if err != nil {
			return err
		}
		s.hs.Write(hdr)
		s.hs.Write(p)
	}
	return nil
}

func (s *Session) serverHello(p []byte) error {
	if len(p) < 2+32+1 || p[0] != 3 || p[1] != 3 {
		return fmt.Errorf("ServerHello: bad version or length %d", len(p))
	}
	random := p[2:34]
	p = p[34:]
	idLen := int(p[0])
	if len(p) != 1+idLen+3 {
		return fmt.Errorf("ServerHello: %d bytes after the random", len(p))
	}
	p = p[1+idLen:]
	if suite := binary.BigEndian.Uint16(p); suite != suiteECDHECDSAAES256 {
		return fmt.Errorf("ServerHello: cipher suite 0x%04x", suite)
	}
	if p[2] != 0 {
		return fmt.Errorf("ServerHello: compression method %d", p[2])
	}
	s.serverRandom = append([]byte(nil), random...)
	return nil
}

func certRequest(p []byte) error {
	if len(p) != 4 {
		return fmt.Errorf("CertificateRequest: %d bytes", len(p))
	}
	if alg := binary.BigEndian.Uint16(p); alg != certReqSigAlg {
		return fmt.Errorf("CertificateRequest: signature algorithm 0x%04x", alg)
	}
	if n := binary.BigEndian.Uint16(p[2:]); n != 0 {
		return errors.New("CertificateRequest: non-empty CA list")
	}
	return nil
}

func (s *Session) serverFinished(p []byte) error {
	if s.master == nil {
		return errors.New("Finished before key exchange")
	}
	want := prf(s.master, concat([]byte("server finished"), s.hs.Sum(nil)), 12)
	if !hmac.Equal(p, want) {
		return errors.New("sensor's Finished does not verify")
	}
	return nil
}

// --- encoding helpers ---

func recordHeader(t byte, n int) []byte { return concat([]byte{t, 3, 3}, u16(n)) }

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func u24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
