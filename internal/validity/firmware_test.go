package validity

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func fakeFwextFile(imgLen int) ([]byte, []byte, []byte) {
	img := bytes.Repeat([]byte{0x5a}, imgLen)
	for i := range img {
		img[i] = byte(i * 7)
	}
	sig := bytes.Repeat([]byte{0x51}, fwextSignatureLen)
	return concat([]byte("Synaptics fwext header\r\n\x1a"), img, sig), img, sig
}

func TestParseFwext(t *testing.T) {
	file, img, sig := fakeFwextFile(10000)
	fw, err := ParseFwext(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fw.Image, img) || !bytes.Equal(fw.Signature, sig) {
		t.Fatal("image or signature split wrongly")
	}
	tooBig, _, _ := fakeFwextFile(0x3e001)
	tests := []struct {
		name string
		file []byte
		want string
	}{
		{"no terminator", []byte("plain text"), "no header terminator"},
		{"nothing but a signature", concat([]byte{0x1a}, make([]byte, fwextSignatureLen)), "after the header"},
		{"larger than the partition", tooBig, "does not fit"},
	}
	for _, tt := range tests {
		if _, err := ParseFwext(tt.file); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
}

// pairedSim returns a simulated sensor that has been paired, and a session
// opened on it as fpd would after the reboot.
func pairedSim(t *testing.T) (*simSensor, *Session) {
	t.Helper()
	s := newSimSensor(t)
	keys := DeriveHostKeys(nil)
	fw := &s.tls.f.fw.PublicKey
	if _, err := Pair(s.link(), keys, fw); err != nil {
		t.Fatal(err)
	}
	sess, err := Open(s.link(), keys, fw)
	if err != nil {
		t.Fatal(err)
	}
	s.cmds = nil
	return s, sess
}

func TestUploadFirmware(t *testing.T) {
	s, sess := pairedSim(t)
	file, img, _ := fakeFwextFile(10000)
	fw, _ := ParseFwext(file)
	got, err := UploadFirmware(sess, fw)
	if err != nil {
		t.Fatal(err)
	}
	if got.BuildTime != 0x5a748cc2 {
		t.Fatalf("firmware info %+v", got)
	}
	if !bytes.Equal(s.parts[PartitionFwext], img) {
		t.Fatal("partition 2 does not hold the image")
	}
	writes := strings.Count(strings.Join(s.cmds, " "), "tls:41")
	if writes != 3 {
		t.Fatalf("%d flash writes for a 10000-byte image, want 3", writes)
	}
	if s.rebooted != 2 {
		t.Fatalf("reboots: %d, want one for pairing and one for the upload", s.rebooted)
	}
	want := "tls:4302 tls:08 tls:07 tls:75"
	if !strings.HasPrefix(strings.Join(s.cmds, " "), want) {
		t.Fatalf("commands start %v, want %s", s.cmds[:4], want)
	}

	// After the reboot the firmware is there and a second upload is refused.
	sess, err = Open(s.link(), DeriveHostKeys(nil), &s.tls.f.fw.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if cur, err := UploadFirmware(sess, fw); !errors.Is(err, ErrFirmwareLoaded) || cur == nil {
		t.Fatalf("second upload: %v, %v", cur, err)
	}
}

func TestUploadFirmwareFailures(t *testing.T) {
	file, _, _ := fakeFwextFile(5000)
	fw, _ := ParseFwext(file)
	tests := []struct {
		name  string
		setup func(s *simSensor)
		want  string
	}{
		{"unexpected register value", func(s *simSensor) { s.fwStatus = 5 }, "reads 5"},
		{"register write refused", func(s *simSensor) { s.fail = "tls:08" }, "prepare"},
		{"register read refused", func(s *simSensor) { s.fail = "tls:07" }, "prepare"},
		{"identify refused", func(s *simSensor) { s.fail = "tls:75" }, "0x75"},
		{"write refused", func(s *simSensor) { s.fail = "tls:41" }, "write at 0x0"},
		{"signature refused", func(s *simSensor) { s.fail = "tls:42" }, "signature"},
		{"firmware query refused", func(s *simSensor) { s.fail = "tls:4302" }, "0x43"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, sess := pairedSim(t)
			tt.setup(s)
			_, err := UploadFirmware(sess, fw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRegisterAndIdentifyReplies(t *testing.T) {
	tests := []struct {
		name string
		run  func(l *Link) error
		rsp  string
		req  string
	}{
		{"short register", func(l *Link) error { _, err := ReadHWReg32(l, 1); return err }, "0000 0102", "07010000000" + "4"},
		{"short identify", func(l *Link) error { _, _, err := IdentifySensor(l); return err }, "0000 00000000", "75"},
		{"identify leading word", func(l *Link) error { _, _, err := IdentifySensor(l); return err }, "0000 01000000 0a00 db00", "75"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: []exchange{{tt.req, tt.rsp}}}
			l, _ := newTestLink(f)
			if err := tt.run(l); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
