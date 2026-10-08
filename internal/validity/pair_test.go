package validity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// simSensor is a sensor with state: an unpartitioned flash until the
// partition command arrives, partition contents that writes change, and
// a reboot that ends the TLS session. It sits on tlsSensor for the
// handshake and the encryption.
type simSensor struct {
	t     *testing.T
	tls   *tlsSensor
	ic    FlashIC
	parts map[uint8][]byte // nil: not partitioned
	// fail answers the named command with status 0x0001.
	fail string
	// fwStatus is what register 0x80002080 reads; fwSigned is set once
	// command 0x42 has accepted a signature.
	fwStatus uint32
	fwSigned bool
	// captures records every command 0x02; frames, when set, supplies
	// the data endpoint's reply to each.
	captures [][]byte
	frames   func() []byte
	// db is the sensor's record store; see db_test.go.
	db *simDB
	// Scanning state, and the interrupts each capture raises; see
	// capture_test.go.
	scan     simScan
	touch    func() [][]byte
	cmds     []string
	rebooted int
}

func newSimSensor(t *testing.T) *simSensor {
	s := &simSensor{t: t, tls: newTLSSensor(t), ic: flashICs[len(flashICs)-1], fwStatus: 2}
	s.tls.plain = s.plainCmd
	s.tls.reply = s.sessionCmd
	return s
}

func (s *simSensor) link() *Link {
	l := NewLink(s.tls, nil)
	l.sleep = func(time.Duration) {}
	return l
}

// name identifies a command for logging and failure injection.
func (s *simSensor) name(req []byte) string {
	switch {
	case bytes.Equal(req, blobInitHardcoded):
		return "init"
	case bytes.Equal(req, blobInitHardcodedCleanSlate):
		return "clean-slate"
	case bytes.Equal(req, blobReset):
		return "reset"
	case bytes.Equal(req, blobDBWriteEnable):
		return "write-enable"
	case len(req) >= 2 && (req[0] == 0x43 || req[0] == 0x3f):
		return hex.EncodeToString(req[:2])
	}
	return hex.EncodeToString(req[:1])
}

var statusFail = []byte{0x01, 0x00}

func (s *simSensor) plainCmd(req []byte) []byte {
	n := s.name(req)
	s.cmds = append(s.cmds, n)
	if n == s.fail {
		return statusFail
	}
	ok := []byte{0, 0}
	switch n {
	case "3e":
		return concat(ok, s.flashInfo())
	case "01":
		return concat(ok, simROM)
	case "19", "init", "clean-slate", "reset", "1a":
		return ok
	case "4302":
		if s.parts == nil {
			return []byte{0xaf, 0x04}
		}
		return []byte{0xb0, 0x04}
	case "4f":
		return s.partition(req)
	case "50":
		zeroes := 20
		p := binary.LittleEndian.AppendUint32(nil, uint32(4+zeroes+len(s.tls.f.ecdhBlock)))
		return concat(ok, p, make([]byte, zeroes), s.tls.f.ecdhBlock)
	case "40":
		return concat(ok, s.readFlash(req))
	}
	s.t.Errorf("sim: unexpected plaintext command %s", n)
	return statusFail
}

func (s *simSensor) sessionCmd(req []byte) []byte {
	n := "tls:" + s.name(req)
	s.cmds = append(s.cmds, n)
	if n == s.fail {
		return statusFail
	}
	ok := []byte{0, 0}
	switch req[0] {
	case 0x01:
		return concat(ok, simROM)
	case 0x02:
		s.captures = append(s.captures, append([]byte(nil), req...))
		if s.frames != nil {
			s.tls.data = s.frames()
		}
		if s.touch != nil {
			s.tls.ints = append(s.tls.ints, s.touch()...)
		}
		return ok
	case 0x39, 0x04, 0x62, 0x69:
		return ok
	case 0x51, 0x68, 0x6b, 0x5e, 0x60:
		return s.scanCmd(req)
	case 0x6f:
		return concat(ok, s.factoryBits())
	case 0x40:
		return concat(ok, s.readFlash(req))
	case 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b:
		return s.dbCmd(req)
	case 0x1a:
		return []byte{0x91, 0x04} // nothing to commit
	case 0x3f:
		if _, exists := s.parts[req[1]]; !exists {
			s.t.Errorf("sim: erase of unknown partition %d", req[1])
		}
		s.parts[req[1]] = nil
		return ok
	case 0x41:
		addr := int(binary.LittleEndian.Uint32(req[5:]))
		size := binary.LittleEndian.Uint32(req[9:])
		if int(size) != len(req)-13 {
			s.t.Errorf("sim: write of %d bytes says %d", len(req)-13, size)
		}
		part := s.parts[req[1]]
		if len(part) < addr+int(size) {
			part = append(part, make([]byte, addr+int(size)-len(part))...)
		}
		copy(part[addr:], req[13:])
		s.parts[req[1]] = part
		return ok
	case 0x43:
		if s.fwSigned {
			return unhex(s.t, fwextReply)
		}
		return []byte{0xb0, 0x04}
	case 0x07:
		if binary.LittleEndian.Uint32(req[1:]) != regFwextStatus {
			s.t.Errorf("sim: read of register %x", req[1:5])
		}
		return binary.LittleEndian.AppendUint32(ok, s.fwStatus)
	case 0x08:
		if binary.LittleEndian.Uint32(req[1:]) != regFwextPrep || binary.LittleEndian.Uint32(req[5:]) != 7 {
			s.t.Errorf("sim: register write %x", req[1:9])
		}
		return ok
	case 0x75:
		return concat(ok, make([]byte, 4), []byte{0x4a, 0x00, 0x90, 0x01})
	case 0x42:
		if n := binary.LittleEndian.Uint16(req[3:]); int(n) != len(req)-5 || n != fwextSignatureLen {
			s.t.Errorf("sim: signature of %d bytes says %d", len(req)-5, n)
		}
		s.fwSigned = true
		return ok
	case 0x05:
		s.rebooted++
		s.tls.endSession()
		return ok
	}
	if n == "tls:write-enable" {
		return ok
	}
	s.t.Errorf("sim: unexpected session command %s", n)
	return statusFail
}

// simROM is this T480's ROM info reply: 6.7 build 164, product 0x30.
var simROM = mustHex("f0b05e54a40000000607013000010000")

// readFlash answers command 0x40 from the stored partitions, with erased
// (never written) bytes reading 0xff as on the chip.
func (s *simSensor) readFlash(req []byte) []byte {
	addr := int(binary.LittleEndian.Uint32(req[5:]))
	size := int(binary.LittleEndian.Uint32(req[9:]))
	part := s.parts[req[1]]
	data := bytes.Repeat([]byte{0xff}, size)
	if addr < len(part) {
		copy(data, part[addr:])
	}
	hdr := binary.LittleEndian.AppendUint32(nil, uint32(size))
	return concat(hdr, []byte{0, 0}, data)
}

// simFactoryValues stands in for the sensor's factory calibration values.
var simFactoryValues = func() []byte {
	v := make([]byte, 0x90)
	for i := range v {
		v[i] = byte(0x78 + i%13)
	}
	return v
}()

// factoryBits answers command 0x6f with subtags 3 and 7, laid out as the
// comment in sensor.py shows a real reply.
func (s *simSensor) factoryBits() []byte {
	entry := func(sub uint16, val []byte) []byte {
		h := binary.LittleEndian.AppendUint32(nil, 0)
		h = binary.LittleEndian.AppendUint16(h, uint16(len(val)))
		h = binary.LittleEndian.AppendUint16(h, 0x0e)
		h = binary.LittleEndian.AppendUint16(h, sub)
		h = binary.LittleEndian.AppendUint16(h, 0x8000)
		return concat(h, val)
	}
	body := binary.LittleEndian.AppendUint32(nil, 7)
	body = binary.LittleEndian.AppendUint32(body, 2)
	return concat(body,
		entry(3, concat([]byte{7, 0, 0, 0}, simFactoryValues)),
		entry(7, concat([]byte{7, 0, 0, 0}, bytes.Repeat([]byte{0x20}, 0x90))))
}

func (s *simSensor) flashInfo() []byte {
	h := make([]byte, flashHeaderLen)
	binary.LittleEndian.PutUint16(h[0:], s.ic.JedecID0)
	binary.LittleEndian.PutUint16(h[2:], s.ic.JedecID1)
	binary.LittleEndian.PutUint16(h[4:], uint16(s.ic.Size/0x100))
	binary.LittleEndian.PutUint16(h[8:], 0x100)
	if s.parts == nil {
		return h
	}
	binary.LittleEndian.PutUint16(h[12:], uint16(len(flashLayout)))
	for _, p := range flashLayout {
		e := make([]byte, partitionLen)
		e[0], e[1] = p.ID, p.Type
		binary.LittleEndian.PutUint16(e[2:], p.AccessLvl)
		binary.LittleEndian.PutUint32(e[4:], p.Offset)
		binary.LittleEndian.PutUint32(e[8:], p.Size)
		h = append(h, e...)
	}
	return h
}

// partition checks command 0x4f the way the sensor would have to, takes
// the host key from the certificate, and answers with the sensor's
// certificate for the TLS partition.
func (s *simSensor) partition(req []byte) []byte {
	if !bytes.Equal(req[:5], []byte{0x4f, 0, 0, 0, 0}) {
		s.t.Errorf("sim: partition prefix %x", req[:5])
	}
	sections := map[uint16][]byte{}
	var order []uint16
	for b := req[5:]; len(b) > 0; {
		id, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		sections[id] = b[4 : 4+n]
		order = append(order, id)
		b = b[4+n:]
	}
	if !slices.Equal(order, []uint16{0, 1, 5, 3}) {
		s.t.Errorf("sim: sections %v, want [0 1 5 3]", order)
	}
	params := sections[0]
	if binary.LittleEndian.Uint32(params) != s.ic.Size || binary.LittleEndian.Uint32(params[4:]) != s.ic.SectorSize ||
		params[10] != s.ic.SectorEraseCmd {
		s.t.Errorf("sim: flash params %x", params)
	}
	table := sections[1]
	if len(table) != 48*len(flashLayout)+len(blobPartitionSignature) {
		s.t.Errorf("sim: partition table of %d bytes", len(table))
	}
	for i := range flashLayout {
		e := table[48*i:]
		if h := sha256.Sum256(e[:12]); !bytes.Equal(h[:], e[16:48]) || !allZero(e[12:16]) {
			s.t.Errorf("sim: partition entry %d hash", i)
		}
	}
	cert := sections[5]
	pub := hostCertKey(s.t, cert)
	s.tls.hostPub = pub
	if !bytes.Equal(sections[3], blobCrtHardcoded) {
		s.t.Error("sim: section 3 is not the fixed certificate")
	}
	s.parts = map[uint8][]byte{}
	for _, p := range flashLayout {
		s.parts[p.ID] = nil
	}
	reply := binary.LittleEndian.AppendUint32(nil, uint32(len(s.tls.f.cert)))
	return concat([]byte{0, 0}, reply, s.tls.f.cert, []byte("unparsed tail"))
}

// hostCertKey checks a host certificate's signature by hsKey and returns
// the key it certifies.
func hostCertKey(t *testing.T, cert []byte) *ecdsa.PublicKey {
	t.Helper()
	if len(cert) != hostCertLen {
		t.Fatalf("host cert is %d bytes", len(cert))
	}
	msg := cert[:0xb8]
	n := binary.LittleEndian.Uint32(cert[0xb8:])
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(&hsKey().PublicKey, h[:], cert[0xbc:0xbc+n]) {
		t.Fatal("host cert signature does not verify")
	}
	pt := concat([]byte{4}, reversed(msg[0x08:0x28]), reversed(msg[0x4c:0x6c]))
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestHsKeyMatchesReference(t *testing.T) {
	d, _ := hsKey().Bytes()
	if hex.EncodeToString(d) != "e8a2a2b6656254d6acb0ef479cae4140c7e8e260db3f642e35d4099c01b36a86" {
		t.Fatalf("hs_key = %x", d)
	}
}

// The message half of make_cert() for refPrivD's public key, from the
// reference; the signature half is randomised.
const refCertMsg = "1700000020000000c3d234a29ad117c9afb65c2311e04d3a09c01802ec307c155cb058a2cf34dfbb" +
	"0000000000000000000000000000000000000000000000000000000000000000000000005cf2c5e9" +
	"c20a1f5639a550e5c5b85ca296dceb2f87369dfc48ee96cdaecfea6b000000000000000000000000" +
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000" +
	"000000000000000000000000000000000000000000000000"

func TestMakeHostCertMatchesReference(t *testing.T) {
	k, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHex(refPrivD))
	cert, err := makeHostCert(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cert[:0xb8]) != refCertMsg {
		t.Fatalf("cert message %x", cert[:0xb8])
	}
	if !hostCertKey(t, cert).Equal(&k.PublicKey) {
		t.Fatal("cert certifies another key")
	}
}

func TestPairThenOpen(t *testing.T) {
	s := newSimSensor(t)
	keys := DeriveHostKeys(bytes.Repeat([]byte{0x42}, 32))
	fw := &s.tls.f.fw.PublicKey
	l := s.link()
	if err := Pair(l, keys, fw); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"3e", "01", "19", "4302", "init", "clean-slate", "reset", "4f", "01", "50", "1a",
		"tls:write-enable", "tls:3f01", "tls:1a",
		"tls:write-enable", "tls:3f02", "tls:1a",
		"tls:write-enable", "tls:3f05", "tls:1a",
		"tls:write-enable", "tls:3f06", "tls:1a",
		"tls:write-enable", "tls:3f04", "tls:1a",
		"tls:write-enable", "tls:41", "tls:1a",
		"tls:05",
	}
	if strings.Join(s.cmds, " ") != strings.Join(want, " ") {
		t.Fatalf("commands:\n got %v\nwant %v", s.cmds, want)
	}
	if s.rebooted != 1 {
		t.Fatalf("rebooted %d times", s.rebooted)
	}
	tlsPart := s.parts[PartitionTLS]
	if len(tlsPart) != tlsPartitionLen {
		t.Fatalf("tls partition holds %d bytes", len(tlsPart))
	}

	// What pairing wrote is what a later start reads back.
	p, err := ParseTLSFlash(tlsPart, keys, fw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Cert, s.tls.f.cert) || !p.HostKey.PublicKey.Equal(s.tls.hostPub) {
		t.Fatal("stored pairing does not match what the sensor certified")
	}

	s.cmds = nil
	sess, err := Open(s.link(), keys, fw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetRomInfo(sess); err != nil {
		t.Fatal(err)
	}

	other := DeriveHostKeys(bytes.Repeat([]byte{0x43}, 32))
	s.tls.endSession()
	if _, err := Open(s.link(), other, fw); !errors.Is(err, ErrForeignPairing) {
		t.Fatalf("open under another identity: %v", err)
	}
	if err := Pair(s.link(), keys, fw); !errors.Is(err, ErrAlreadyPartitioned) {
		t.Fatalf("pairing twice: %v", err)
	}
}

func TestOpenUnpaired(t *testing.T) {
	s := newSimSensor(t)
	if _, err := Open(s.link(), DeriveHostKeys(nil), &s.tls.f.fw.PublicKey); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("err = %v", err)
	}
}

func TestPairFailures(t *testing.T) {
	for _, step := range []string{
		// Not 4302: send_init reads any non-zero status there as "no
		// firmware" and carries on, as it should.
		"3e", "01", "19", "init", "reset", "4f", "50",
		"tls:write-enable", "tls:3f01", "tls:41", "tls:05",
	} {
		t.Run(step, func(t *testing.T) {
			s := newSimSensor(t)
			s.fail = step
			if err := Pair(s.link(), DeriveHostKeys(nil), &s.tls.f.fw.PublicKey); err == nil {
				t.Fatal("pairing succeeded")
			}
		})
	}
	t.Run("unknown flash chip", func(t *testing.T) {
		s := newSimSensor(t)
		s.ic.JedecID0 = 0x99
		err := Pair(s.link(), DeriveHostKeys(nil), &s.tls.f.fw.PublicKey)
		if err == nil || !strings.Contains(err.Error(), "unknown flash chip") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("sensor key not signed by the firmware key", func(t *testing.T) {
		s := newSimSensor(t)
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err := Pair(s.link(), DeriveHostKeys(nil), &other.PublicKey)
		if err == nil || !strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(strings.Join(s.cmds, " "), "tls:") {
			t.Fatal("a session command ran after the key check failed")
		}
	})
}

func TestOpenFailures(t *testing.T) {
	for _, step := range []string{"3e", "init", "40"} {
		t.Run(step, func(t *testing.T) {
			s := newSimSensor(t)
			keys := DeriveHostKeys(nil)
			if err := Pair(s.link(), keys, &s.tls.f.fw.PublicKey); err != nil {
				t.Fatal(err)
			}
			s.fail = step
			if _, err := Open(s.link(), keys, &s.tls.f.fw.PublicKey); err == nil {
				t.Fatal("open succeeded")
			}
		})
	}
}

func TestCleanupsStatus(t *testing.T) {
	tests := []struct {
		rsp string
		ok  bool
	}{{"0000", true}, {"9104", true}, {"0100", false}}
	for _, tt := range tests {
		f := &fakeSensor{t: t, script: []exchange{{"1a", tt.rsp}}}
		l, _ := newTestLink(f)
		if err := callCleanups(l); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.rsp, err)
		}
	}
}

func TestWithCleanupsKeepsFirstError(t *testing.T) {
	f := &fakeSensor{t: t, script: []exchange{{"1a", "0100"}}}
	l, _ := newTestLink(f)
	first := errors.New("first")
	if err := withCleanups(l, func() error { return first }); !errors.Is(err, first) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookupFlashIC(t *testing.T) {
	// What this T480's sensor reported.
	ic, ok := LookupFlashIC(FlashInfo{JedecID0: 0xc8, JedecID1: 0x40, Blocks: 0x1000, BlockSize: 0x100})
	if !ok || ic.Name != "GD25Q80C" || ic.SectorSize != 0x1000 || ic.SectorEraseCmd != 0x20 {
		t.Fatalf("got %+v, %v", ic, ok)
	}
	if _, ok := LookupFlashIC(FlashInfo{JedecID0: 0xc8, JedecID1: 0x40, Blocks: 0x800, BlockSize: 0x100}); ok {
		t.Fatal("matched on ids alone")
	}
}

func TestBlobsLoaded(t *testing.T) {
	sizes := map[string]int{
		"init_hardcoded": 581, "init_hardcoded_clean_slate": 741, "reset_blob": 12037,
		"db_write_enable": 3621, "crt_hardcoded": 420, "partition_signature": 256,
	}
	for name, n := range sizes {
		if got := len(loadBlob(name)); got != n {
			t.Errorf("%s: %d bytes, want %d", name, got, n)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("missing blob did not panic")
		}
	}()
	loadBlob("nope")
}

func TestFactoryReset(t *testing.T) {
	wipe := "10" + strings.Repeat("00", 0x61)
	tests := []struct {
		name    string
		script  []exchange
		wantErr string
	}{
		{"ok", []exchange{{hex.EncodeToString(blobReset), "0000"}, {wipe, "0000"}, {"050200", "0000"}}, ""},
		{"reset refused", []exchange{{hex.EncodeToString(blobReset), "0100"}}, "reset program"},
		{"wipe refused", []exchange{{hex.EncodeToString(blobReset), "0000"}, {wipe, "0100"}}, "wipe"},
		{"reboot refused", []exchange{{hex.EncodeToString(blobReset), "0000"}, {wipe, "0000"}, {"050200", "0100"}}, "0x05"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: tt.script}
			l, _ := newTestLink(f)
			err := FactoryReset(l)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				f.done()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
