package validity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// Vectors produced by running the reference's prf() and set_hwkey() in
// Python, so they check the port rather than this code against itself.
func TestPRFMatchesReference(t *testing.T) {
	got := prf([]byte("secret-key"), []byte("test labelseed-bytes"), 0x50)
	want := "4a8d9fb0f135ff20d2f60f343a1dc418949e7908b8540c57b052217ac8cc78cb" +
		"9ac4b7ad5660e01e22e12151ffca5aea6e34a751045d513f8679382940fdd5f3" +
		"ea0d9750cfd9582a99979341e6df64b8"
	if hex.EncodeToString(got) != want {
		t.Fatalf("prf = %x", got)
	}
	// Shorter outputs are prefixes of longer ones.
	if short := prf([]byte("secret-key"), []byte("test labelseed-bytes"), 5); !bytes.Equal(short, got[:5]) {
		t.Fatalf("prf(5) = %x", short)
	}
}

// Shared by the TLS flash tests: the keys for this identity.
var testIdentity = DMIIdentity("ThinkPad T480", "R90TEST01")

func TestDeriveHostKeysMatchesReference(t *testing.T) {
	if string(testIdentity) != "ThinkPad T480\x00R90TEST01\x00" {
		t.Fatalf("identity %q", testIdentity)
	}
	k := DeriveHostKeys(testIdentity)
	if hex.EncodeToString(k.Encryption) != "97a2d1dc600e66d49e92862f633f6e89dd44963c005beb34a6d40902fa7796c4" {
		t.Errorf("encryption key %x", k.Encryption)
	}
	if hex.EncodeToString(k.Validation) != "292eeee1aa6477a397951af9bbba79503338f60b461b29a9b6452483ec861044" {
		t.Errorf("validation key %x", k.Validation)
	}
}

func TestCBCRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	for _, n := range []int{0, 1, 15, 16, 17, 100} {
		plain := bytes.Repeat([]byte{0xa5}, n)
		c, err := cbcEncrypt(key, tlsPad(append([]byte(nil), plain...)))
		if err != nil {
			t.Fatal(err)
		}
		m, err := cbcDecrypt(key, c)
		if err != nil {
			t.Fatal(err)
		}
		if m, err = tlsUnpad(m); err != nil || !bytes.Equal(m, plain) {
			t.Fatalf("n=%d: got %x, %v", n, m, err)
		}
	}
}

func TestCBCErrors(t *testing.T) {
	key := make([]byte, 32)
	for _, n := range []int{0, 16, 33} {
		if _, err := cbcDecrypt(key, make([]byte, n)); !errors.Is(err, errCBC) {
			t.Errorf("decrypt %d bytes: %v", n, err)
		}
	}
	if _, err := cbcDecrypt(make([]byte, 5), make([]byte, 32)); err == nil {
		t.Error("decrypt with a bad key size succeeded")
	}
	if _, err := cbcEncrypt(make([]byte, 5), make([]byte, 16)); err == nil {
		t.Error("encrypt with a bad key size succeeded")
	}
}

func TestPadding(t *testing.T) {
	tests := []struct {
		name  string
		unpad func([]byte) ([]byte, error)
		in    string
		want  string
		bad   bool
	}{
		{"tls one byte", tlsUnpad, "aabb00", "aabb", false},
		{"tls full block", tlsUnpad, "aa" + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "aa", false},
		{"tls overruns", tlsUnpad, "aa05", "", true},
		{"tls empty", tlsUnpad, "", "", true},
		{"pkcs7 one byte", pkcs7Unpad, "aabb01", "aabb", false},
		{"pkcs7 zero", pkcs7Unpad, "aabb00", "", true},
		{"pkcs7 too big", pkcs7Unpad, "aa11", "", true},
		{"pkcs7 overruns", pkcs7Unpad, "aa03", "", true},
		{"pkcs7 empty", pkcs7Unpad, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.unpad(unhex(t, tt.in))
			if tt.bad {
				if !errors.Is(err, errCBC) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || hex.EncodeToString(got) != tt.want {
				t.Fatalf("got %x, %v", got, err)
			}
		})
	}
	for n := range 33 {
		b := make([]byte, n)
		if p := pkcs7Pad(b); len(p)%16 != 0 || len(p) <= n {
			t.Fatalf("pkcs7Pad(%d) = %d bytes", n, len(p))
		} else if u, err := pkcs7Unpad(p); err != nil || len(u) != n {
			t.Fatalf("pkcs7 round trip %d: %d, %v", n, len(u), err)
		}
	}
}

func TestMustHexPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	mustHex("zz")
}
