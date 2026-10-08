package validity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The TLS flash partition (partition 1) holds the pairing as a list of
// blocks: u16 id, u16 size (little-endian), SHA-256 of the body, body.
const (
	tlsBlockEnd     = 0xffff
	tlsBlockPrivKey = 4 // host private key, encrypted under HostKeys
	tlsBlockCert    = 3 // host certificate, sent in the handshake
	tlsBlockECDH    = 6 // sensor's static ECDH key, signed by Synaptics
	tlsBlockHdrLen  = 4 + sha256.Size
)

// PartitionTLS is the flash partition holding the pairing blocks.
const PartitionTLS = 0x01

// ErrForeignPairing means the private-key block does not authenticate
// under this host's keys: the sensor was paired by another host (or under
// a different identity) and needs a factory reset before it can be paired
// here.
var ErrForeignPairing = errors.New("sensor is paired with another host")

// FirmwarePublicKey is the key Synaptics signs the sensor's ECDH key with.
// The reference notes it is hardcoded per firmware revision in the Windows
// driver; this is the one it ships.
func FirmwarePublicKey() *ecdsa.PublicKey {
	pt := append([]byte{4}, mustHex(
		"f727653b4e16ce0665a6894d7f3a30d7d0a0be310d1292a743671fdf69f6a8d3"+
			"a85538f8b6bec50d6eef8bd5f4d07a886243c58b2393948df761a84721a6ca94")...)
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		panic(err)
	}
	return k
}

// Pairing is the key material read back from the TLS flash partition.
type Pairing struct {
	HostKey   *ecdsa.PrivateKey // signs the handshake's CertificateVerify
	Cert      []byte            // sent as the client certificate
	SensorKey *ecdh.PublicKey   // the sensor's static ECDH key
}

// ParseTLSFlash parses the TLS partition. fwKey verifies the sensor's
// ECDH key; pass FirmwarePublicKey() outside tests.
func ParseTLSFlash(data []byte, keys HostKeys, fwKey *ecdsa.PublicKey) (*Pairing, error) {
	p := &Pairing{}
	for len(data) > 0 {
		if len(data) < tlsBlockHdrLen {
			return nil, fmt.Errorf("tls flash: %d-byte block header: %w", len(data), ErrShortReply)
		}
		id := binary.LittleEndian.Uint16(data[0:])
		size := int(binary.LittleEndian.Uint16(data[2:]))
		sum := data[4:tlsBlockHdrLen]
		data = data[tlsBlockHdrLen:]
		if id == tlsBlockEnd {
			break
		}
		if len(data) < size {
			return nil, fmt.Errorf("tls flash: block %d: %d of %d bytes: %w", id, len(data), size, ErrShortReply)
		}
		body := data[:size]
		data = data[size:]
		if h := sha256.Sum256(body); !bytes.Equal(h[:], sum) {
			return nil, fmt.Errorf("tls flash: block %d: hash mismatch", id)
		}
		var err error
		switch id {
		case tlsBlockPrivKey:
			p.HostKey, err = parsePrivBlock(body, keys)
		case tlsBlockCert:
			p.Cert = append([]byte(nil), body...)
		case tlsBlockECDH:
			p.SensorKey, err = parseECDHBlock(body, fwKey)
		case 0, 1, 2:
			if !allZero(body) {
				err = errors.New("expected an empty block")
			}
		}
		// Unknown ids, including 5 (a fixed blob the reference writes and
		// never reads back), are skipped as the reference skips them.
		if err != nil {
			return nil, fmt.Errorf("tls flash: block %d: %w", id, err)
		}
	}
	switch {
	case p.HostKey == nil:
		return nil, errors.New("tls flash: no private key block")
	case p.Cert == nil:
		return nil, errors.New("tls flash: no certificate block")
	case p.SensorKey == nil:
		return nil, errors.New("tls flash: no ecdh block")
	}
	return p, nil
}

// Private key block: 0x02, IV || AES-256-CBC(x || y || d, PKCS#7), then
// HMAC-SHA256 over the IV and ciphertext. Coordinates and scalar are
// 32-byte little-endian.
func parsePrivBlock(body []byte, keys HostKeys) (*ecdsa.PrivateKey, error) {
	if len(body) < 1+sha256.Size || body[0] != 2 {
		return nil, errors.New("unknown private key format")
	}
	c, mac := body[1:len(body)-sha256.Size], body[len(body)-sha256.Size:]
	if !hmac.Equal(mac, hmacSHA256(keys.Validation, c)) {
		return nil, ErrForeignPairing
	}
	m, err := cbcDecrypt(keys.Encryption, c)
	if err != nil {
		return nil, err
	}
	if m, err = pkcs7Unpad(m); err != nil {
		return nil, err
	}
	if len(m) < 0x60 {
		return nil, fmt.Errorf("private key: %d bytes: %w", len(m), ErrShortReply)
	}
	// Only d is used: the reference reports that x and y come back zero
	// after pairing with recent Windows drivers.
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), reversed(m[0x40:0x60]))
}

// ECDH block: a 0x90-byte key structure holding x at 0x08 and y at 0x4c
// (32-byte little-endian each), then u32 signature length, a DER ECDSA
// signature over the key structure, and zero padding.
const ecdhKeyLen = 0x90

func parseECDHBlock(body []byte, fwKey *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	if len(body) < ecdhKeyLen+4 {
		return nil, fmt.Errorf("ecdh: %d bytes: %w", len(body), ErrShortReply)
	}
	key, rest := body[:ecdhKeyLen], body[ecdhKeyLen:]
	pt := make([]byte, 0, 65)
	pt = append(pt, 4)
	pt = append(pt, reversed(key[0x08:0x28])...)
	pt = append(pt, reversed(key[0x4c:0x6c])...)
	pub, err := ecdh.P256().NewPublicKey(pt)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	n := int(binary.LittleEndian.Uint32(rest))
	rest = rest[4:]
	if n > len(rest) {
		return nil, fmt.Errorf("ecdh: %d-byte signature in %d bytes: %w", n, len(rest), ErrShortReply)
	}
	if !allZero(rest[n:]) {
		return nil, errors.New("ecdh: non-zero bytes after the signature")
	}
	h := sha256.Sum256(key)
	if !ecdsa.VerifyASN1(fwKey, h[:], rest[:n]) {
		return nil, errors.New("ecdh: firmware signature does not verify")
	}
	return pub, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// EncryptHostKey builds the private key block for priv: the inverse of
// parsePrivBlock, as the reference's encrypt_key writes it during pairing.
func EncryptHostKey(priv *ecdsa.PrivateKey, keys HostKeys) ([]byte, error) {
	pub, err := priv.PublicKey.Bytes() // 04 || X || Y
	if err != nil {
		return nil, err
	}
	d, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	m := concat(reversed(pub[1:33]), reversed(pub[33:65]), reversed(d))
	c, err := cbcEncrypt(keys.Encryption, pkcs7Pad(m))
	if err != nil {
		return nil, err
	}
	return concat([]byte{2}, c, hmacSHA256(keys.Validation, c)), nil
}

// tlsFlashBlock frames one block of the TLS partition.
func tlsFlashBlock(id uint16, body []byte) []byte {
	h := sha256.Sum256(body)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint16(hdr, id)
	binary.LittleEndian.PutUint16(hdr[2:], uint16(len(body)))
	return concat(hdr, h[:], body)
}
