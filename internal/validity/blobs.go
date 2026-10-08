package validity

import (
	"embed"
	"strings"
)

// The blobs are signed command programs and fixed certificates taken from
// python-validity (blobs_9a.py, tls.py, init_flash.py). They are kept as
// hex text so they diff and review like source.
//
//go:embed blobs/*.hex
var blobFS embed.FS

func loadBlob(name string) []byte {
	b, err := blobFS.ReadFile("blobs/" + name + ".hex")
	if err != nil {
		panic(err)
	}
	return mustHex(strings.Join(strings.Fields(string(b)), ""))
}

var (
	// Start-up programs sent by send_init: the first always, the second
	// when no firmware extension is loaded.
	blobInitHardcoded           = loadBlob("init_hardcoded")
	blobInitHardcodedCleanSlate = loadBlob("init_hardcoded_clean_slate")
	// Sent before partitioning and as the first step of a factory reset.
	blobReset = loadBlob("reset_blob")
	// Unlocks flash writes; every erase and write is wrapped in it.
	blobDBWriteEnable = loadBlob("db_write_enable")
	// A fixed certificate the host sends during partitioning and stores
	// as TLS block 5. Its meaning is not documented by the reference.
	blobCrtHardcoded = loadBlob("crt_hardcoded")
	// Synaptics' signature over the partition table below.
	blobPartitionSignature = loadBlob("partition_signature")
)

// FlashIC describes a flash chip the sensor may be built with. Only the
// fields pairing uses are kept from the reference's table.
type FlashIC struct {
	Name           string
	Size           uint32
	JedecID0       uint16
	JedecID1       uint16
	SectorSize     uint32
	SectorEraseCmd uint8
}

var flashICs = []FlashIC{
	{"M25P05-A", 65536, 0x20, 0x20, 0x8000, 0xd8},
	{"M25P10-A", 131072, 0x20, 0x20, 0x8000, 0xd8},
	{"M25P20", 262144, 0x20, 0x20, 0x10000, 0xd8},
	{"M25P40", 524288, 0x20, 0x20, 0x10000, 0xd8},
	{"M25P80", 1048576, 0x20, 0x20, 0x10000, 0xd8},
	{"M25P16", 2097152, 0x20, 0x20, 0x10000, 0xd8},
	{"M25P32", 4194304, 0x20, 0x20, 0x10000, 0xd8},
	{"M25P64", 8388608, 0x20, 0x20, 0x10000, 0xd8},
	{"SST25VF040B", 524288, 0xbf, 0x25, 0x10000, 0xd8},
	{"W25X10A", 131072, 0xef, 0x30, 0x1000, 0x20},
	{"W25X20A", 262144, 0xef, 0x30, 0x1000, 0x20},
	{"W25X40A", 524288, 0xef, 0x30, 0x1000, 0x20},
	{"W25X80A", 1048576, 0xef, 0x30, 0x1000, 0x20},
	{"W25Q40B", 524288, 0xef, 0x40, 0x1000, 0x20},
	{"W25Q80B", 1048576, 0xef, 0x40, 0x1000, 0x20},
	{"MX25L4006E", 524288, 0xc2, 0x20, 0x1000, 0x20},
	{"EN25Q40", 524288, 0x1c, 0x30, 0x1000, 0x20},
	{"MX25V8035F", 1048576, 0xc2, 0x23, 0x1000, 0x20},
	{"AT25SF081", 1048576, 0x1f, 0x85, 0x1000, 0x20},
	{"GD25Q80C", 1048576, 0xc8, 0x40, 0x1000, 0x20},
}

// LookupFlashIC matches the chip the sensor reported, as the reference
// does: both JEDEC ids and the total size.
func LookupFlashIC(fi FlashInfo) (FlashIC, bool) {
	size := uint32(fi.Blocks) * uint32(fi.BlockSize)
	for _, ic := range flashICs {
		if ic.JedecID0 == fi.JedecID0 && ic.JedecID1 == fi.JedecID1 && ic.Size == size {
			return ic, true
		}
	}
	return FlashIC{}, false
}

// Partition layout for every sensor but 138a:0090, from init_flash.py.
var flashLayout = []Partition{
	{ID: 1, Type: 4, AccessLvl: 7, Offset: 0x00001000, Size: 0x00001000}, // TLS (cert store)
	{ID: 2, Type: 1, AccessLvl: 2, Offset: 0x00002000, Size: 0x0003e000}, // firmware extension
	{ID: 5, Type: 5, AccessLvl: 3, Offset: 0x00040000, Size: 0x00008000}, // unknown
	{ID: 6, Type: 6, AccessLvl: 3, Offset: 0x00048000, Size: 0x00008000}, // calibration data
	{ID: 4, Type: 3, AccessLvl: 5, Offset: 0x00050000, Size: 0x00080000}, // template database
}
