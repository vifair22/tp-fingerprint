package validity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// statusNothingToCommit is what command 0x1a returns when no flash
// transaction is open; the reference treats it as success.
const statusNothingToCommit Status = 0x0491

// SendInit is the reference's send_init: ROM info, command 0x19 and the
// firmware header, then the start-up program, and a second program when
// no firmware extension is loaded. It runs before anything touches the
// protected flash (python-validity #272).
func SendInit(l *Link) error {
	if _, err := l.CmdOK([]byte{0x01}); err != nil {
		return err
	}
	if _, err := l.CmdOK([]byte{0x19}); err != nil {
		return err
	}
	fwst, _, err := l.Cmd([]byte{0x43, PartitionFwext})
	if err != nil {
		return err
	}
	if _, err := l.CmdOK(blobInitHardcoded); err != nil {
		return fmt.Errorf("start-up program: %w", err)
	}
	if fwst != StatusOK {
		l.log.Debug("no firmware extension, sending the clean-slate program", "status", fwst)
		if _, _, err := l.Cmd(blobInitHardcodedCleanSlate); err != nil {
			return fmt.Errorf("clean-slate program: %w", err)
		}
	}
	return nil
}

// callCleanups closes the flash transaction a write opened (command 0x1a).
func callCleanups(c Commander) error {
	st, _, err := c.Cmd([]byte{0x1a})
	if err != nil {
		return err
	}
	if st != StatusOK && st != statusNothingToCommit {
		return &StatusError{Cmd: 0x1a, Status: st}
	}
	return nil
}

// withCleanups runs op and then closes the flash transaction, as the
// reference's try/finally does. op's error wins over the cleanup's.
func withCleanups(c Commander, op func() error) error {
	err := op()
	if cerr := callCleanups(c); err == nil {
		err = cerr
	}
	return err
}

// EraseFlash erases one partition (command 0x3f).
func EraseFlash(c Commander, partition uint8) error {
	if _, err := c.CmdOK(blobDBWriteEnable); err != nil {
		return fmt.Errorf("write enable: %w", err)
	}
	return withCleanups(c, func() error {
		_, err := c.CmdOK([]byte{0x3f, partition})
		return err
	})
}

// WriteFlash writes data at addr in partition (command 0x41).
func WriteFlash(c Commander, partition uint8, addr uint32, data []byte) error {
	// The reference does not check the write-enable status here, unlike
	// in EraseFlash; the write's own status is what decides.
	if _, _, err := c.Cmd(blobDBWriteEnable); err != nil {
		return fmt.Errorf("write enable: %w", err)
	}
	req := make([]byte, 13, 13+len(data))
	req[0], req[1], req[2] = 0x41, partition, 1
	binary.LittleEndian.PutUint32(req[5:], addr)
	binary.LittleEndian.PutUint32(req[9:], uint32(len(data)))
	req = append(req, data...)
	return withCleanups(c, func() error {
		_, err := c.CmdOK(req)
		return err
	})
}

// Reboot restarts the sensor (command 05 02 00). The device drops off the
// bus and re-enumerates, so the caller's handle is finished afterwards.
func Reboot(c Commander) error {
	_, err := c.CmdOK([]byte{0x05, 0x02, 0x00})
	return err
}

// hsKey is the key the reference signs the host certificate with. It is
// derived from the shared hardcoded password, so every host has it; the
// certificate proves nothing beyond "made by a driver".
func hsKey() *ecdsa.PrivateKey {
	seed := concat([]byte("HS_KEY_PAIR_GEN"), passwordHardcoded[0x10:], []byte{0xaa, 0xaa})
	d := reversed(prf(passwordHardcoded[:0x10], seed, 0x20))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		panic(err)
	}
	return k
}

// hostCertLen is the size the reference pads the host certificate to; it
// flags the figure as uncertain.
const hostCertLen = 444

// makeHostCert builds the certificate for pub sent in partition block 5:
// a key structure (0x17, 0x20, x, zeroes, y, zeroes, coordinates
// little-endian), u32 signature length, DER signature by hsKey, zero
// padding.
func makeHostCert(pub *ecdsa.PublicKey) ([]byte, error) {
	pt, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 8, 0xb8)
	binary.LittleEndian.PutUint32(msg, 0x17)
	binary.LittleEndian.PutUint32(msg[4:], 0x20)
	msg = append(msg, reversed(pt[1:33])...)
	msg = append(msg, make([]byte, 0x24)...)
	msg = append(msg, reversed(pt[33:65])...)
	msg = append(msg, make([]byte, 0x4c)...)
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, hsKey(), h[:])
	if err != nil {
		return nil, err
	}
	msg = binary.LittleEndian.AppendUint32(msg, uint32(len(sig)))
	msg = append(msg, sig...)
	if len(msg) > hostCertLen {
		return nil, fmt.Errorf("host certificate is %d bytes", len(msg))
	}
	return append(msg, make([]byte, hostCertLen-len(msg))...), nil
}

// withHdr frames one section of the partition command: u16 id, u16
// length, body.
func withHdr(id uint16, body []byte) []byte {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint16(hdr, id)
	binary.LittleEndian.PutUint16(hdr[2:], uint16(len(body)))
	return concat(hdr, body)
}

// partitionCmd builds command 0x4f, which formats the flash: flash
// parameters, the signed partition table, our certificate and the fixed
// certificate blob.
func partitionCmd(ic FlashIC, hostCert []byte) []byte {
	params := make([]byte, 12)
	binary.LittleEndian.PutUint32(params, ic.Size)
	binary.LittleEndian.PutUint32(params[4:], ic.SectorSize)
	params[10] = ic.SectorEraseCmd

	var table []byte
	for _, p := range flashLayout {
		e := make([]byte, 12)
		e[0], e[1] = p.ID, p.Type
		binary.LittleEndian.PutUint16(e[2:], p.AccessLvl)
		binary.LittleEndian.PutUint32(e[4:], p.Offset)
		binary.LittleEndian.PutUint32(e[8:], p.Size)
		h := sha256.Sum256(e)
		table = concat(table, e, make([]byte, 4), h[:])
	}
	return concat(
		[]byte{0x4f, 0, 0, 0, 0},
		withHdr(0, params),
		withHdr(1, concat(table, blobPartitionSignature)),
		withHdr(5, hostCert),
		withHdr(3, blobCrtHardcoded),
	)
}

// ecdhReplyTail is how much of command 0x50's reply is the ECDH block;
// zeroes precede it.
const ecdhReplyTail = 400

// ErrAlreadyPartitioned is returned by Pair for a sensor whose flash has
// a partition table: pairing would overwrite it, and the safe way to do
// that is a factory reset first.
var ErrAlreadyPartitioned = errors.New("sensor flash is already partitioned")

// Pair formats an unpartitioned sensor and pairs it with this host, keys
// being the HostKeys of the host's identity. It follows the reference's
// init_flash with send_init moved first. On success the sensor has been
// told to reboot: close the handle and find the device again.
//
// The sensor is in a bad state if this fails after the partition command:
// partitioned but without the TLS block, which only a factory reset
// recovers. The steps between are short and none of them is expected to
// fail on a sensor that accepted the partition command.
//
// It returns the sensor's ECDH public key, which the host pins
// (docs/DESIGN.md, finding F1).
func Pair(l *Link, keys HostKeys, fwKey *ecdsa.PublicKey) ([]byte, error) {
	fi, err := GetFlashInfo(l)
	if err != nil {
		return nil, err
	}
	if len(fi.Partitions) > 0 {
		return nil, ErrAlreadyPartitioned
	}
	ic, ok := LookupFlashIC(fi)
	if !ok {
		return nil, fmt.Errorf("unknown flash chip: jedec %04x:%04x, %d x %d bytes",
			fi.JedecID0, fi.JedecID1, fi.Blocks, fi.BlockSize)
	}
	l.log.Info("flash chip", "name", ic.Name, "size", ic.Size)

	if err := SendInit(l); err != nil {
		return nil, fmt.Errorf("start-up: %w", err)
	}

	// Everything that can fail without touching the sensor happens
	// before the partition command.
	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privBlob, err := EncryptHostKey(host, keys)
	if err != nil {
		return nil, err
	}
	hostCert, err := makeHostCert(&host.PublicKey)
	if err != nil {
		return nil, err
	}

	// The reference sends the reset program immediately before
	// partitioning; what it resets is not documented.
	if _, err := l.CmdOK(blobReset); err != nil {
		return nil, fmt.Errorf("reset program: %w", err)
	}
	l.log.Info("partitioning flash")
	p, err := l.CmdOK(partitionCmd(ic, hostCert))
	if err != nil {
		return nil, fmt.Errorf("partition: %w", err)
	}
	if len(p) < 4 || int(binary.LittleEndian.Uint32(p)) > len(p)-4 {
		return nil, fmt.Errorf("partition: certificate reply: %w", ErrShortReply)
	}
	tlsCert := append([]byte(nil), p[4:4+binary.LittleEndian.Uint32(p)]...)

	if _, err := GetRomInfo(l); err != nil {
		return nil, err
	}

	var ecdhReply []byte
	err = withCleanups(l, func() error {
		var err error
		ecdhReply, err = l.CmdOK([]byte{0x50})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sensor key: %w", err)
	}
	if len(ecdhReply) < 4+ecdhReplyTail || int(binary.LittleEndian.Uint32(ecdhReply)) != len(ecdhReply) {
		return nil, fmt.Errorf("sensor key: %d-byte reply: %w", len(ecdhReply), ErrShortReply)
	}
	if !allZero(ecdhReply[4 : len(ecdhReply)-ecdhReplyTail]) {
		return nil, errors.New("sensor key: non-zero bytes before the key")
	}
	ecdhBlob := ecdhReply[len(ecdhReply)-ecdhReplyTail:]
	sensorKey, err := parseECDHBlock(ecdhBlob, fwKey)
	if err != nil {
		return nil, fmt.Errorf("sensor key: %w", err)
	}

	sess, err := OpenSession(l, &Pairing{HostKey: host, Cert: tlsCert, SensorKey: sensorKey})
	if err != nil {
		return nil, err
	}
	l.log.Info("session open, erasing partitions")
	for _, part := range flashLayout {
		if err := EraseFlash(sess, part.ID); err != nil {
			return nil, fmt.Errorf("erase partition %d: %w", part.ID, err)
		}
	}
	l.log.Info("writing pairing to the tls partition")
	if err := WriteFlash(sess, PartitionTLS, 0, makeTLSFlash(privBlob, tlsCert, ecdhBlob)); err != nil {
		return nil, fmt.Errorf("write tls partition: %w", err)
	}
	return sensorKey.Bytes(), Reboot(sess)
}

// tlsPartitionLen is what the reference writes to the TLS partition: the
// blocks, padded with 0xff to one 4 KiB block.
const tlsPartitionLen = 0x1000

// makeTLSFlash lays out the TLS partition as the reference's
// make_tls_flash does.
func makeTLSFlash(privBlob, cert, ecdhBlob []byte) []byte {
	b := concat(
		tlsFlashBlock(0, []byte{0}),
		tlsFlashBlock(tlsBlockPrivKey, privBlob),
		tlsFlashBlock(tlsBlockCert, cert),
		tlsFlashBlock(5, blobCrtHardcoded),
		tlsFlashBlock(1, make([]byte, 0x100)),
		tlsFlashBlock(2, make([]byte, 0x100)),
		tlsFlashBlock(tlsBlockECDH, ecdhBlob),
	)
	for len(b) < tlsPartitionLen {
		b = append(b, 0xff)
	}
	return b
}

// FactoryReset wipes the sensor's pairing and enrolled prints, as the
// reference's factory_reset does: the reset program, command 0x10 with
// 0x61 zero bytes, and a reboot. It needs no session and no start-up, so
// it also recovers a sensor left partitioned without a TLS block. The
// host secret is untouched and can pair the sensor again.
func FactoryReset(l *Link) error {
	if _, err := l.CmdOK(blobReset); err != nil {
		return fmt.Errorf("reset program: %w", err)
	}
	if _, err := l.CmdOK(append([]byte{0x10}, make([]byte, 0x61)...)); err != nil {
		return fmt.Errorf("wipe: %w", err)
	}
	return Reboot(l)
}
