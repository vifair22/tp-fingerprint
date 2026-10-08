package validity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Made by the reference's encrypt_key() under testIdentity's keys, for
// the private scalar below.
const (
	refPrivBlob = "0212fb50a73e4f31a71964b27ea4632dff4a2672447c1f5a5535248701c1d131" +
		"38c93681cef6164e1548ee299fe6991bf0c6f2626a58d2bf9cfe3ce2d53af922" +
		"76ed936775c49df3eac22c18a82cd777b8a52d1daf2b28da1438855554277f43" +
		"e9b57241f859ac4e8cb00b791db5798425aaef049317f16b0cc40d6a22da8ad6" +
		"ba04fc7e142c88573fc54ea59a86aa48a12dded25c36bbcd7a7a5f7c4f64fd8d23"
	refPrivD = "1b2a1f7c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
)

// pairingFixture is a consistent set of keys standing in for a paired
// sensor: our host key, the sensor's ECDH key, and a firmware key that
// signs it in place of Synaptics'.
type pairingFixture struct {
	keys      HostKeys
	host      *ecdsa.PrivateKey
	sensor    *ecdh.PrivateKey
	fw        *ecdsa.PrivateKey
	cert      []byte
	ecdhBlock []byte
}

func newPairingFixture(t *testing.T) *pairingFixture {
	t.Helper()
	f := &pairingFixture{keys: DeriveHostKeys(testIdentity), cert: bytes.Repeat([]byte{0xce}, 400)}
	var err error
	if f.host, err = ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHex(refPrivD)); err != nil {
		t.Fatal(err)
	}
	if f.sensor, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.fw, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	f.ecdhBlock = makeECDHBlock(t, f.sensor.PublicKey(), f.fw, 400)
	return f
}

// makeECDHBlock lays out the sensor's ECDH key the way command 0x50
// returns it, padded with zeroes to size.
func makeECDHBlock(t *testing.T, pub *ecdh.PublicKey, fw *ecdsa.PrivateKey, size int) []byte {
	t.Helper()
	pt := pub.Bytes()
	key := make([]byte, ecdhKeyLen)
	copy(key[0x08:], reversed(pt[1:33]))
	copy(key[0x4c:], reversed(pt[33:65]))
	h := sha256.Sum256(key)
	sig, err := ecdsa.SignASN1(rand.Reader, fw, h[:])
	if err != nil {
		t.Fatal(err)
	}
	b := binary.LittleEndian.AppendUint32(key, uint32(len(sig)))
	b = append(b, sig...)
	return append(b, make([]byte, size-len(b))...)
}

func (f *pairingFixture) flash(t *testing.T) []byte {
	t.Helper()
	priv, err := EncryptHostKey(f.host, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	// The reference's make_tls_flash order, then the end marker and
	// erased flash.
	b := concat(
		tlsFlashBlock(0, []byte{0}),
		tlsFlashBlock(tlsBlockPrivKey, priv),
		tlsFlashBlock(tlsBlockCert, f.cert),
		tlsFlashBlock(5, []byte("a blob the parser skips")),
		tlsFlashBlock(1, make([]byte, 0x100)),
		tlsFlashBlock(2, make([]byte, 0x100)),
		tlsFlashBlock(tlsBlockECDH, f.ecdhBlock),
	)
	return append(b, bytes.Repeat([]byte{0xff}, 0x1000-len(b))...)
}

func TestReferencePrivBlobDecrypts(t *testing.T) {
	k, err := parsePrivBlock(mustHex(refPrivBlob), DeriveHostKeys(testIdentity))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := k.Bytes()
	if !bytes.Equal(d, mustHex(refPrivD)) {
		t.Fatalf("d = %x", d)
	}
}

func TestPrivBlobUnderAnotherIdentity(t *testing.T) {
	other := DeriveHostKeys(DMIIdentity("ThinkPad T480", "SOMEONEELSE"))
	if _, err := parsePrivBlock(mustHex(refPrivBlob), other); !errors.Is(err, ErrForeignPairing) {
		t.Fatalf("err = %v, want ErrForeignPairing", err)
	}
}

func TestPrivBlobErrors(t *testing.T) {
	keys := DeriveHostKeys(testIdentity)
	signed := func(c []byte) []byte { return concat([]byte{2}, c, hmacSHA256(keys.Validation, c)) }
	short, _ := cbcEncrypt(keys.Encryption, pkcs7Pad(make([]byte, 0x40)))
	tests := []struct {
		name string
		blob []byte
	}{
		{"wrong prefix", append([]byte{3}, make([]byte, 64)...)},
		{"too short", []byte{2, 1, 2}},
		{"not whole blocks", signed(make([]byte, 20))},
		{"bad padding", signed(make([]byte, 48))},
		{"short key material", signed(short)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parsePrivBlock(tt.blob, keys); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseTLSFlash(t *testing.T) {
	f := newPairingFixture(t)
	p, err := ParseTLSFlash(f.flash(t), f.keys, &f.fw.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HostKey.Equal(f.host) || !bytes.Equal(p.Cert, f.cert) || !p.SensorKey.Equal(f.sensor.PublicKey()) {
		t.Fatal("pairing does not match the fixture")
	}
}

func TestParseTLSFlashErrors(t *testing.T) {
	f := newPairingFixture(t)
	priv, _ := EncryptHostKey(f.host, f.keys)
	cert := tlsFlashBlock(tlsBlockCert, f.cert)
	pk := tlsFlashBlock(tlsBlockPrivKey, priv)
	ec := tlsFlashBlock(tlsBlockECDH, f.ecdhBlock)
	otherFW, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	corrupt := append([]byte(nil), cert...)
	corrupt[len(corrupt)-1] ^= 1

	tests := []struct {
		name string
		data []byte
		fw   *ecdsa.PublicKey
		want string
	}{
		{"no private key", concat(cert, ec), nil, "no private key"},
		{"no cert", concat(pk, ec), nil, "no certificate"},
		{"no ecdh", concat(pk, cert), nil, "no ecdh"},
		{"end marker stops the scan", concat(pk, cert, tlsFlashBlock(tlsBlockEnd, nil), ec), nil, "no ecdh"},
		{"hash mismatch", concat(pk, corrupt, ec), nil, "hash mismatch"},
		{"truncated header", concat(pk, cert, ec, []byte{1, 2}), nil, "block header"},
		{"truncated body", concat(pk, cert, ec[:len(ec)-1]), nil, "of 400 bytes"},
		{"dirty empty block", concat(tlsFlashBlock(1, []byte{1}), pk, cert, ec), nil, "empty block"},
		{"foreign signature", concat(pk, cert, ec), &otherFW.PublicKey, "does not verify"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := tt.fw
			if fw == nil {
				fw = &f.fw.PublicKey
			}
			_, err := ParseTLSFlash(tt.data, f.keys, fw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseECDHBlockErrors(t *testing.T) {
	f := newPairingFixture(t)
	fw := &f.fw.PublicKey
	offCurve := append([]byte(nil), f.ecdhBlock...)
	offCurve[0x08] ^= 1
	trailing := append([]byte(nil), f.ecdhBlock...)
	trailing[len(trailing)-1] = 1
	hugeSig := append([]byte(nil), f.ecdhBlock...)
	binary.LittleEndian.PutUint32(hugeSig[ecdhKeyLen:], 10000)
	tests := []struct {
		name string
		body []byte
	}{
		{"short", f.ecdhBlock[:ecdhKeyLen]},
		{"point off the curve", offCurve},
		{"bytes after the signature", trailing},
		{"signature length overruns", hugeSig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseECDHBlock(tt.body, fw); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestFirmwarePublicKey(t *testing.T) {
	k := FirmwarePublicKey()
	if k.X.Text(16) != "f727653b4e16ce0665a6894d7f3a30d7d0a0be310d1292a743671fdf69f6a8d3" {
		t.Fatalf("x = %s", k.X.Text(16))
	}
}

func TestReadFlash(t *testing.T) {
	tests := []struct {
		name    string
		rsp     string
		want    string
		wantErr bool
	}{
		{"data", "0000 03000000 0000 aabbcc", "aabbcc", false},
		{"short header", "0000 0000", "", true},
		{"short data", "0000 05000000 0000 aabbcc", "", true},
		{"status", "0100", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: []exchange{{"40010100000010000000100000", tt.rsp}}}
			l, _ := newTestLink(f)
			got, err := ReadFlash(l, PartitionTLS, 0x1000, 0x1000)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil || !bytes.Equal(got, unhex(t, tt.want)) {
				t.Fatalf("got %x, %v", got, err)
			}
		})
	}
}
