package validity

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// ErrNotPaired is returned by Open for a sensor with no partition table.
var ErrNotPaired = errors.New("sensor is not paired")

// Open brings up a paired sensor the way the reference's open_common does
// once pairing exists: start-up programs, the pairing read back from the
// TLS partition, then the handshake. keys are the HostKeys of the
// identity the sensor was paired under; ErrForeignPairing means another.
func Open(l *Link, keys HostKeys, fwKey *ecdsa.PublicKey) (*Session, error) {
	fi, err := GetFlashInfo(l)
	if err != nil {
		return nil, err
	}
	if len(fi.Partitions) == 0 {
		return nil, ErrNotPaired
	}
	if err := SendInit(l); err != nil {
		return nil, fmt.Errorf("start-up: %w", err)
	}
	data, err := ReadFlash(l, PartitionTLS, 0, tlsPartitionLen)
	if err != nil {
		return nil, fmt.Errorf("read tls partition: %w", err)
	}
	pair, err := ParseTLSFlash(data, keys, fwKey)
	if err != nil {
		return nil, err
	}
	return OpenSession(l, pair)
}
