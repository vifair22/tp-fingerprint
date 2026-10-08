package validity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// FirmwareName is the firmware extension file 06cb:009a takes, from
// Lenovo's driver package. The reference notes that the file must match
// the signed blobs rather than the hardware, which is why one file serves
// several sensors.
const FirmwareName = "6_07f_lenovo_mis_qm.xpfwext"

// fwextSignatureLen is the RSA-2048-sized signature at the end of the file.
const fwextSignatureLen = 0x100

// fwextChunk is the most the reference writes in one flash command.
const fwextChunk = 0x1000

// Fwext is a firmware extension ready to upload.
type Fwext struct {
	Image     []byte // written to partition 2
	Signature []byte // written with command 0x42
}

// ParseFwext splits an .xpfwext file: a text header ended by the first
// 0x1a byte, the image, and a 256-byte signature.
func ParseFwext(file []byte) (*Fwext, error) {
	i := bytes.IndexByte(file, 0x1a)
	if i < 0 {
		return nil, errors.New("fwext: no header terminator")
	}
	body := file[i+1:]
	if len(body) <= fwextSignatureLen {
		return nil, fmt.Errorf("fwext: %d bytes after the header: %w", len(body), ErrShortReply)
	}
	img := body[:len(body)-fwextSignatureLen]
	if part := flashLayout[1]; part.ID != PartitionFwext || uint32(len(img)) > part.Size {
		return nil, fmt.Errorf("fwext: %d-byte image does not fit partition %d", len(img), PartitionFwext)
	}
	return &Fwext{Image: img, Signature: body[len(img):]}, nil
}

// ReadHWReg32 reads a 32-bit sensor register (command 0x07).
func ReadHWReg32(c Commander, addr uint32) (uint32, error) {
	req := binary.LittleEndian.AppendUint32([]byte{0x07}, addr)
	p, err := c.CmdOK(append(req, 4))
	if err != nil {
		return 0, err
	}
	if len(p) != 4 {
		return 0, fmt.Errorf("register 0x%08x: %d-byte reply: %w", addr, len(p), ErrShortReply)
	}
	return binary.LittleEndian.Uint32(p), nil
}

// WriteHWReg32 writes a 32-bit sensor register (command 0x08).
func WriteHWReg32(c Commander, addr, val uint32) error {
	req := binary.LittleEndian.AppendUint32([]byte{0x08}, addr)
	req = binary.LittleEndian.AppendUint32(req, val)
	_, err := c.CmdOK(append(req, 4))
	return err
}

// IdentifySensor runs command 0x75 and returns the hardware major and
// minor version the reference looks the sensor model up by.
func IdentifySensor(c Commander) (major, minor uint16, err error) {
	p, err := c.CmdOK([]byte{0x75})
	if err != nil {
		return 0, 0, err
	}
	if len(p) != 8 {
		return 0, 0, fmt.Errorf("identify: %d-byte reply: %w", len(p), ErrShortReply)
	}
	if z := binary.LittleEndian.Uint32(p); z != 0 {
		return 0, 0, fmt.Errorf("identify: leading word 0x%08x, expected zero", z)
	}
	return binary.LittleEndian.Uint16(p[6:]), binary.LittleEndian.Uint16(p[4:]), nil
}

// writeFwSignature runs command 0x42 for partition.
func writeFwSignature(c Commander, partition uint8, sig []byte) error {
	req := []byte{0x42, partition, 0}
	req = binary.LittleEndian.AppendUint16(req, uint16(len(sig)))
	_, err := c.CmdOK(append(req, sig...))
	return err
}

// The reference pokes this register before an upload and checks the other
// reads 2 or 3; it does not know why either.
const (
	regFwextPrep   = 0x8000205c
	regFwextStatus = 0x80002080
)

// ErrFirmwareLoaded is returned by UploadFirmware when the sensor already
// has a firmware extension.
var ErrFirmwareLoaded = errors.New("firmware extension already loaded")

// UploadFirmware writes fw to the firmware partition over an open
// session, as the reference's upload_fwext does, and reboots the sensor.
// It returns the firmware info the sensor reported after the write.
func UploadFirmware(s *Session, fw *Fwext) (*FirmwareInfo, error) {
	cur, _, err := GetFirmwareInfo(s, PartitionFwext)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		return cur, ErrFirmwareLoaded
	}
	if err := WriteHWReg32(s, regFwextPrep, 7); err != nil {
		return nil, fmt.Errorf("prepare: %w", err)
	}
	v, err := ReadHWReg32(s, regFwextStatus)
	if err != nil {
		return nil, fmt.Errorf("prepare: %w", err)
	}
	if v != 2 && v != 3 {
		return nil, fmt.Errorf("prepare: register 0x%08x reads %d, expected 2 or 3", uint32(regFwextStatus), v)
	}
	major, minor, err := IdentifySensor(s)
	if err != nil {
		return nil, err
	}
	s.link.log.Info("uploading firmware", "sensor_major", major, "sensor_minor", minor, "bytes", len(fw.Image))

	for off := 0; off < len(fw.Image); off += fwextChunk {
		end := min(off+fwextChunk, len(fw.Image))
		if err := WriteFlash(s, PartitionFwext, uint32(off), fw.Image[off:end]); err != nil {
			return nil, fmt.Errorf("write at 0x%x: %w", off, err)
		}
	}
	if err := writeFwSignature(s, PartitionFwext, fw.Signature); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	got, _, err := GetFirmwareInfo(s, PartitionFwext)
	if err != nil {
		return nil, err
	}
	if got == nil {
		return nil, errors.New("sensor reports no firmware after the upload")
	}
	return got, Reboot(s)
}
