package validity

import (
	"encoding/binary"
	"fmt"
)

// RomInfo is the reply to command 0x01: the sensor's mask ROM version.
type RomInfo struct {
	Timestamp uint32
	Build     uint32
	Major     uint8
	Minor     uint8
	Product   uint8
	Unknown1  uint8
}

// GetRomInfo runs command 0x01.
func GetRomInfo(l *Link) (RomInfo, error) {
	p, err := l.CmdOK([]byte{0x01})
	if err != nil {
		return RomInfo{}, err
	}
	return parseRomInfo(p)
}

// Layout <LLBBxBxxxB: two u32s, major, minor, a pad byte, product, three
// pad bytes, one more byte of unknown meaning.
func parseRomInfo(p []byte) (RomInfo, error) {
	if len(p) < 0x10 {
		return RomInfo{}, fmt.Errorf("rom info: %d bytes: %w", len(p), ErrShortReply)
	}
	return RomInfo{
		Timestamp: binary.LittleEndian.Uint32(p[0:]),
		Build:     binary.LittleEndian.Uint32(p[4:]),
		Major:     p[8],
		Minor:     p[9],
		Product:   p[11],
		Unknown1:  p[15],
	}, nil
}

// Partition is one entry of the sensor's flash partition table.
type Partition struct {
	ID        uint8
	Type      uint8
	AccessLvl uint16
	Offset    uint32
	Size      uint32
}

// FlashInfo is the reply to command 0x3e.
type FlashInfo struct {
	// Uninitialised is set when the sensor answered with a bare status
	// word, which is what flash that has never been formatted returns
	// (python-validity #272). The other fields are then zero.
	Uninitialised bool
	JedecID0      uint16
	JedecID1      uint16
	Blocks        uint16
	Unknown0      uint16
	BlockSize     uint16
	Unknown1      uint16
	Partitions    []Partition
}

// GetFlashInfo runs command 0x3e.
func GetFlashInfo(l *Link) (FlashInfo, error) {
	p, err := l.CmdOK([]byte{0x3e})
	if err != nil {
		return FlashInfo{}, err
	}
	return parseFlashInfo(p)
}

const (
	flashHeaderLen = 0x0e
	partitionLen   = 0x0c
)

func parseFlashInfo(p []byte) (FlashInfo, error) {
	if len(p) == 0 {
		return FlashInfo{Uninitialised: true}, nil
	}
	if len(p) < flashHeaderLen {
		return FlashInfo{}, fmt.Errorf("flash info: %d-byte header: %w", len(p), ErrShortReply)
	}
	u16 := func(off int) uint16 { return binary.LittleEndian.Uint16(p[off:]) }
	fi := FlashInfo{
		JedecID0:  u16(0),
		JedecID1:  u16(2),
		Blocks:    u16(4),
		Unknown0:  u16(6),
		BlockSize: u16(8),
		Unknown1:  u16(10),
	}
	count := int(u16(12))
	body := p[flashHeaderLen:]
	if len(body) < count*partitionLen {
		return FlashInfo{}, fmt.Errorf("flash info: %d partitions in %d bytes: %w", count, len(body), ErrShortReply)
	}
	fi.Partitions = make([]Partition, count)
	for i := range fi.Partitions {
		e := body[i*partitionLen:]
		fi.Partitions[i] = Partition{
			ID:        e[0],
			Type:      e[1],
			AccessLvl: binary.LittleEndian.Uint16(e[2:]),
			Offset:    binary.LittleEndian.Uint32(e[4:]),
			Size:      binary.LittleEndian.Uint32(e[8:]),
		}
	}
	return fi, nil
}

// Module is one firmware module listed in a partition header.
type Module struct {
	Type    uint16
	Subtype uint16
	Major   uint16
	Minor   uint16
	Size    uint32
}

// FirmwareInfo is the reply to command 0x43 for one partition.
type FirmwareInfo struct {
	Major     uint16
	Minor     uint16
	BuildTime uint32 // unix seconds
	Modules   []Module
}

// PartitionFwext holds the firmware extension the host uploads.
const PartitionFwext = 0x02

// GetFirmwareInfo runs command 0x43 for partition. When the partition
// holds no firmware, or does not exist, it returns nil with the status
// that said so and no error.
func GetFirmwareInfo(l *Link, partition uint8) (*FirmwareInfo, Status, error) {
	st, p, err := l.Cmd([]byte{0x43, partition})
	if err != nil {
		return nil, 0, err
	}
	switch st {
	case StatusOK:
		fi, err := parseFirmwareInfo(p)
		return fi, st, err
	case StatusNoFirmware, StatusNoPartition:
		return nil, st, nil
	default:
		return nil, st, &StatusError{Cmd: 0x43, Status: st}
	}
}

const (
	fwHeaderLen = 0x0a
	moduleLen   = 0x0c
)

func parseFirmwareInfo(p []byte) (*FirmwareInfo, error) {
	if len(p) < fwHeaderLen {
		return nil, fmt.Errorf("firmware info: %d-byte header: %w", len(p), ErrShortReply)
	}
	fi := &FirmwareInfo{
		Major:     binary.LittleEndian.Uint16(p[0:]),
		Minor:     binary.LittleEndian.Uint16(p[2:]),
		BuildTime: binary.LittleEndian.Uint32(p[6:]),
	}
	count := int(binary.LittleEndian.Uint16(p[4:]))
	body := p[fwHeaderLen:]
	if len(body) < count*moduleLen {
		return nil, fmt.Errorf("firmware info: %d modules in %d bytes: %w", count, len(body), ErrShortReply)
	}
	fi.Modules = make([]Module, count)
	for i := range fi.Modules {
		e := body[i*moduleLen:]
		fi.Modules[i] = Module{
			Type:    binary.LittleEndian.Uint16(e[0:]),
			Subtype: binary.LittleEndian.Uint16(e[2:]),
			Major:   binary.LittleEndian.Uint16(e[4:]),
			Minor:   binary.LittleEndian.Uint16(e[6:]),
			Size:    binary.LittleEndian.Uint32(e[8:]),
		}
	}
	return fi, nil
}

// Report is what Probe learns about the sensor.
type Report struct {
	Flash FlashInfo
	Rom   RomInfo
	// Cmd19 is the payload of command 0x19, whose meaning is unknown; the
	// reference sends it during start-up and ignores the reply.
	Cmd19 []byte
	// Fwext is nil when no firmware extension is loaded; FwextStatus then
	// says why.
	Fwext       *FirmwareInfo
	FwextStatus Status
}

// Probe runs the read-only commands the reference sends before it first
// writes anything to the sensor, in the reference's order: flash info
// (init_flash), then ROM info, 0x19 and the fwext header (send_init). It
// never changes sensor state, so it is safe on a sensor of unknown history.
func Probe(l *Link) (Report, error) {
	var r Report
	var err error
	if r.Flash, err = GetFlashInfo(l); err != nil {
		return r, err
	}
	if r.Rom, err = GetRomInfo(l); err != nil {
		return r, err
	}
	if r.Cmd19, err = l.CmdOK([]byte{0x19}); err != nil {
		return r, err
	}
	if r.Fwext, r.FwextStatus, err = GetFirmwareInfo(l, PartitionFwext); err != nil {
		return r, err
	}
	return r, nil
}
