//go:build hwprobe

package validity

// Probes of the real sensor, for questions about its protocol that only
// hardware answers. Never part of the normal suite: build them with
//
//	go test -c -tags hwprobe -o build/hwprobe ./internal/validity
//
// and run as root with fpd stopped, e.g.
//
//	sudo build/hwprobe -test.v -test.run TestProbeHandshakes
//
// They use the installed host secret and calibration data.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/usbfs"
)

const (
	probeSecret = "/var/lib/fpd/host-secret"
	probeCalib  = "/var/lib/fpd/calib-data.bin"
)

// probeLink opens the real sensor's USB device.
func probeLink(t *testing.T) (*Link, *usbfs.Device) {
	t.Helper()
	info, err := usbfs.System.Find(VendorID, ProductID)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := usbfs.Open(usbfs.System, info, 0)
	if err != nil {
		t.Fatalf("%v (is fpd stopped?)", err)
	}
	return NewLink(dev, slog.New(slog.DiscardHandler)), dev
}

func probeKeys(t *testing.T) HostKeys {
	t.Helper()
	secret, err := os.ReadFile(probeSecret)
	if err != nil {
		t.Fatal(err)
	}
	return DeriveHostKeys(secret)
}

// F3: how does the sensor take many sessions without a reboot? The
// reference warns it eventually runs out of memory.
func TestProbeHandshakes(t *testing.T) {
	const rounds = 100
	l, dev := probeLink(t)
	defer dev.Close()
	keys := probeKeys(t)
	var total, worst time.Duration
	var sess *Session
	for i := 1; i <= rounds; i++ {
		start := time.Now()
		var err error
		sess, err = Open(l, keys, FirmwarePublicKey())
		d := time.Since(start)
		if err != nil {
			t.Fatalf("open %d failed after %v: %v", i, d, err)
		}
		if _, err := GetRomInfo(sess); err != nil {
			t.Fatalf("session %d does not answer: %v", i, err)
		}
		total += d
		worst = max(worst, d)
		if i%10 == 0 {
			fmt.Printf("%3d sessions: mean %v, worst %v\n", i, (total / time.Duration(i)).Round(time.Millisecond), worst.Round(time.Millisecond))
		}
	}
	// The latest session still drives the sensor properly.
	sen, err := OpenSensor(sess, mustRead(t, probeCalib))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sen.Calibrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if fi, _, err := GetFirmwareInfo(sess, PartitionFwext); err != nil || fi == nil {
		t.Fatalf("firmware after %d sessions: %v, %v", rounds, fi, err)
	}
	fmt.Println("after", rounds, "sessions the sensor still opens, calibrates and reports its firmware")
	if err := Reboot(sess); err != nil {
		t.Logf("reboot: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// F2 and F4: what does the match result (command 0x60) hold, and what does
// it return after a finger that did not match, with and without the 0x62
// cleanup in between? Four touches, prompted on stdout.
func TestProbeMatchResults(t *testing.T) {
	l, dev := probeLink(t)
	defer dev.Close()
	sess, err := Open(l, probeKeys(t), FirmwarePublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sen, err := OpenSensor(sess, mustRead(t, probeCalib))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sen.Calibrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	rounds := []struct {
		say     string
		cleanup bool
	}{
		{"touch with your ENROLLED finger", true},
		{"touch with a DIFFERENT finger", true},
		{"touch with your ENROLLED finger again (no cleanup after this one)", false},
		{"touch with a DIFFERENT finger again", true},
	}
	for i, r := range rounds {
		fmt.Printf("\n== round %d: %s\n", i+1, r.say)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		for {
			if err := sen.Glow(true); err != nil {
				t.Fatal(err)
			}
			err := sen.capture(ctx, ModeIdentify)
			if err == nil {
				break
			}
			if !retryable(err) {
				cancel()
				t.Fatal(err)
			}
			fmt.Println("   scan not usable, touch again:", err)
		}
		cancel()
		req := append([]byte{0x5e, 2, 0xff}, u16le(0, 0, 1, 0, 0)...)
		st, p, err := sess.Cmd(req)
		fmt.Printf("   5e  -> status %s %s (err %v)\n", st, hex.EncodeToString(p), err)
		ictx, icancel := context.WithTimeout(context.Background(), 10*time.Second)
		b, err := l.WaitInt(ictx)
		icancel()
		fmt.Printf("   int -> %s (err %v)\n", hex.EncodeToString(b), err)
		st, p, err = sess.Cmd([]byte{0x60, 0, 0, 0, 0})
		fmt.Printf("   60  -> status %s, %d bytes (err %v)\n", st, len(p), err)
		dumpFields(p)
		if r.cleanup {
			st, p, err = sess.Cmd([]byte{0x62, 0, 0, 0, 0})
			fmt.Printf("   62  -> status %s %s (err %v)\n", st, hex.EncodeToString(p), err)
		}
		_ = sen.Glow(false)
	}
}

// dumpFields prints a 0x60 reply's tagged fields.
func dumpFields(p []byte) {
	if len(p) < 2 {
		fmt.Printf("        raw %s\n", hex.EncodeToString(p))
		return
	}
	body := p[2:]
	for len(body) >= 4 {
		tag, n := int(body[0])|int(body[1])<<8, int(body[2])|int(body[3])<<8
		if len(body)-4 < n {
			break
		}
		fmt.Printf("        field %d (%d bytes): %s\n", tag, n, hex.EncodeToString(body[4:4+n]))
		body = body[4+n:]
	}
	if len(body) > 0 {
		fmt.Printf("        trailing %s\n", hex.EncodeToString(body))
	}
}

// F3 again: with a session up, plaintext commands are refused (0x0315),
// so a full re-open fails. Does a bare handshake, renewing the session in
// place, work, and how often?
func TestProbeRenewHandshake(t *testing.T) {
	const rounds = 100
	l, dev := probeLink(t)
	defer dev.Close()
	keys := probeKeys(t)
	var err error
	if _, err = GetFlashInfo(l); err != nil {
		t.Fatal(err)
	}
	if err := SendInit(l); err != nil {
		t.Fatal(err)
	}
	if probeTLSCopy, err = ReadFlash(l, PartitionTLS, 0, tlsPartitionLen); err != nil {
		t.Fatal(err)
	}
	// The pairing as Open would read it; every renewal reuses it.
	data, err := readTLSPartitionViaFreshProbe(t)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ParseTLSFlash(data, keys, FirmwarePublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var total, worst time.Duration
	var sess *Session
	for i := 1; i <= rounds; i++ {
		start := time.Now()
		sess, err = OpenSession(l, pair)
		d := time.Since(start)
		if err != nil {
			t.Fatalf("renewal %d failed after %v: %v", i, d, err)
		}
		if _, err := GetRomInfo(sess); err != nil {
			t.Fatalf("renewed session %d does not answer: %v", i, err)
		}
		total += d
		worst = max(worst, d)
		if i%10 == 0 {
			fmt.Printf("%3d renewals: mean %v, worst %v\n", i, (total / time.Duration(i)).Round(time.Millisecond), worst.Round(time.Millisecond))
		}
	}
	if fi, _, err := GetFirmwareInfo(sess, PartitionFwext); err != nil || fi == nil {
		t.Fatalf("firmware after %d renewals: %v, %v", rounds, fi, err)
	}
	fmt.Println("after", rounds, "renewals the session still answers")
	_ = Reboot(sess)
}

// readTLSPartitionViaFreshProbe is a stand-in: the TLS partition can only
// be read in plaintext, before a session exists, so the probe keeps a copy
// from the first open in probeTLSCopy.
var probeTLSCopy []byte

func readTLSPartitionViaFreshProbe(t *testing.T) ([]byte, error) {
	t.Helper()
	if probeTLSCopy == nil {
		return nil, fmt.Errorf("no copy of the TLS partition")
	}
	return probeTLSCopy, nil
}

// Escape hatch for a session the host lost but the sensor kept: does a USB
// port reset clear it, so that a full open works again?
func TestProbeResetClearsSession(t *testing.T) {
	// Starts from whatever the sensor holds; run it right after a probe
	// that left a session up, to test the stuck state.
	l, dev := probeLink(t)
	keys := probeKeys(t)
	st, _, err := l.Cmd([]byte{0x3e})
	fmt.Printf("plaintext flash info before the reset: status %s (err %v)\n", st, err)
	start := time.Now()
	if err := dev.Reset(); err != nil {
		fmt.Printf("reset: %v\n", err)
	}
	dev.Close()
	// After a reset the device may come back at a new address.
	var info usbfs.Info
	for i := 0; i < 50; i++ {
		if info, err = usbfs.System.Find(VendorID, ProductID); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	dev2, err := usbfs.Open(usbfs.System, info, 0)
	for i := 0; err != nil && i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		dev2, err = usbfs.Open(usbfs.System, info, 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer dev2.Close()
	l2 := NewLink(dev2, slog.New(slog.DiscardHandler))
	sess, err := Open(l2, keys, FirmwarePublicKey())
	if err != nil {
		t.Fatalf("full open after a USB reset (%v later): %v", time.Since(start), err)
	}
	fmt.Printf("full open after a USB reset worked, %v after the reset (bus %d addr %d)\n",
		time.Since(start).Round(time.Millisecond), info.Bus, info.Addr)
	_ = Reboot(sess)
}

// Does a refused handshake (the sensor's alert) end the session it had, so
// that a full open works straight after? Ten cycles, timed.
func TestProbeAlertEndsSession(t *testing.T) {
	l, dev := probeLink(t)
	defer dev.Close()
	keys := probeKeys(t)
	sess, err := Open(l, keys, FirmwarePublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pair := sess.pair
	for i := 1; i <= 10; i++ {
		st, _, _ := l.Cmd([]byte{0x3e})
		_, herr := OpenSession(l, pair)
		st2, _, _ := l.Cmd([]byte{0x3e})
		start := time.Now()
		sess, err = Open(l, keys, FirmwarePublicKey())
		d := time.Since(start)
		if err != nil {
			t.Fatalf("cycle %d: plaintext with session %s; hello: %v; plaintext after %s; full open: %v",
				i, st, herr, st2, err)
		}
		if _, err := GetRomInfo(sess); err != nil {
			t.Fatalf("cycle %d: new session does not answer: %v", i, err)
		}
		fmt.Printf("cycle %2d: plaintext %s -> hello refused (%v) -> plaintext %s -> full open %v\n",
			i, st, herr != nil, st2, d.Round(time.Millisecond))
	}
	_ = Reboot(sess)
}

// F2: is the match result's field 4 (32 bytes, stable per enrolled finger)
// a SHA-256 of something in the finger record the host wrote?
func TestProbeFingerRecordHash(t *testing.T) {
	l, dev := probeLink(t)
	defer dev.Close()
	sess, err := Open(l, probeKeys(t), FirmwarePublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = Reboot(sess) }()
	db := NewDB(sess)
	stg, err := db.Storage()
	if err != nil {
		t.Fatal(err)
	}
	u, err := db.LookupUser(stg.ID, UIDSID(1000))
	if err != nil || u == nil {
		t.Fatalf("user: %v, %v", u, err)
	}
	for _, f := range u.Fingers {
		rec, err := db.RecordValue(f.ID)
		if err != nil {
			t.Fatal(err)
		}
		v := rec.Value
		fmt.Printf("finger record %d (subtype %d): %d bytes\n", f.ID, f.Subtype, len(v))
		// fingerData: u16 subtype, u16 3, u16 len, u16 0x20, then
		// u16 1, u16 len, template, u16 2, u16 len, tid, then 32 zeros.
		if len(v) < 12 {
			continue
		}
		tl := int(v[10]) | int(v[11])<<8
		template := v[12 : 12+tl]
		rest := v[12+tl:]
		il := int(rest[2]) | int(rest[3])<<8
		tid := rest[4 : 4+il]
		fmt.Printf("  template %d bytes, tid %d bytes: %s\n", len(template), len(tid), hex.EncodeToString(tid))
		for name, b := range map[string][]byte{
			"whole value": v, "template": template, "tid": tid,
			"template without its 0x38 header": template[min(len(template), enrollMagicLen):],
		} {
			h := sha256.Sum256(b)
			fmt.Printf("  sha256(%s) = %s\n", name, hex.EncodeToString(h[:]))
		}
		kids, err := db.RecordChildren(f.ID)
		if err == nil {
			fmt.Printf("  children: %+v\n", kids.Children)
		}
	}
}
