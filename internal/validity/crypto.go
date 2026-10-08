package validity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// prf is the TLS 1.2 PRF with SHA-256 (P_SHA256 of RFC 5246 section 5).
// The label is part of seed, as the reference passes it.
func prf(secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	a := hmacSHA256(secret, seed)
	for len(out) < n {
		out = append(out, hmacSHA256(secret, a, seed)...)
		a = hmacSHA256(secret, a)
	}
	return out[:n]
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Constants every Synaptics driver shares, taken from the reference.
var (
	passwordHardcoded = mustHex("717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033")
	gwkSignHardcoded  = mustHex("3a4c76b76a97981d1274247e166610e77f4d9c9d07d3c728e532916bdd28b454")
)

// HostKeys are the pre-TLS keys derived from the host's identity. They
// encrypt and authenticate the host's private key, which pairing stores in
// the sensor's flash, so a sensor paired under one identity cannot be
// opened under another.
type HostKeys struct {
	Encryption []byte // AES-256
	Validation []byte // HMAC-SHA256
}

// DMIIdentity is the identity the reference (and, by its account, the
// Windows driver) binds pairing to: the DMI product name and serial
// number, each NUL-terminated.
func DMIIdentity(productName, serial string) []byte {
	id := make([]byte, 0, len(productName)+len(serial)+2)
	id = append(id, productName...)
	id = append(id, 0)
	id = append(id, serial...)
	return append(id, 0)
}

// DeriveHostKeys turns an identity into HostKeys.
func DeriveHostKeys(identity []byte) HostKeys {
	enc := prf(passwordHardcoded, append([]byte("GWK"), identity...), 0x20)
	val := prf(enc, append([]byte("GWK_SIGN"), gwkSignHardcoded...), 0x20)
	return HostKeys{Encryption: enc, Validation: val}
}

var errCBC = errors.New("malformed cbc payload")

// cbcEncrypt returns IV || AES-CBC(key, plain). plain must already be a
// whole number of blocks.
func cbcEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize+len(plain))
	iv := out[:aes.BlockSize]
	rand.Read(iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aes.BlockSize:], plain)
	return out, nil
}

// cbcDecrypt takes IV || ciphertext and returns the padded plaintext.
func cbcDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < 2*aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: %d bytes", errCBC, len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv, c := data[:aes.BlockSize], data[aes.BlockSize:]
	out := make([]byte, len(c))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, c)
	return out, nil
}

// TLS-style padding: n bytes of value n-1, 1 <= n <= 16.
func tlsPad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	for range n {
		b = append(b, byte(n-1))
	}
	return b
}

// tlsUnpad drops TLS-style padding. Like the reference it trusts the last
// byte for the length and leaves checking to the record MAC that follows;
// it only guards against a length that would run off the buffer.
func tlsUnpad(b []byte) ([]byte, error) {
	if len(b) == 0 || int(b[len(b)-1])+1 > len(b) {
		return nil, fmt.Errorf("%w: bad padding", errCBC)
	}
	return b[:len(b)-1-int(b[len(b)-1])], nil
}

// pkcs7Unpad drops PKCS#7 padding, which the private-key blob uses.
func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty", errCBC)
	}
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return nil, fmt.Errorf("%w: bad padding", errCBC)
	}
	return b[:len(b)-n], nil
}

func pkcs7Pad(b []byte) []byte {
	n := aes.BlockSize - len(b)%aes.BlockSize
	for range n {
		b = append(b, byte(n))
	}
	return b
}

// reversed returns a reversed copy: the sensor stores curve coordinates
// and scalars little-endian, Go's crypto wants them big-endian.
func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}
