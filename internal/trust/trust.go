// Package trust keeps what the host knows independently of the sensor:
// which sensor it paired with (finding F1 in docs/DESIGN.md) and which
// templates it enrolled for whom (finding F2). A sensor can be swapped or
// re-provisioned by someone with physical access; these let fpd refuse a
// sensor that is not the one it paired, and a match on a template it did
// not enroll.
//
// Both live beside the host secret in /var/lib/fpd, root-only.
package trust

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"git.airies.net/vifair22/t480-fingerprint/internal/atomicfile"
)

// Default locations.
const (
	DefaultPinPath    = "/var/lib/fpd/sensor-pin"
	DefaultLedgerPath = "/var/lib/fpd/enrolled"
)

// ErrSensorMismatch means the attached sensor is not the one this host
// paired with.
var ErrSensorMismatch = errors.New("sensor does not match the pinned sensor")

func pinOf(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}

// WritePin pins the sensor whose ECDH public key is key, replacing any
// earlier pin. Pairing calls it.
func WritePin(path string, key []byte) error {
	return atomicfile.Write(path, []byte(pinOf(key)+"\n"), 0o600)
}

// CheckPin compares the sensor's key with the pin. With no pin yet, it
// pins this sensor and reports adopted: trust on first use, for a pairing
// made before pinning existed.
func CheckPin(path string, key []byte) (adopted bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, WritePin(path, key)
	}
	if err != nil {
		return false, err
	}
	want := strings.TrimSpace(string(b))
	if subtle.ConstantTimeCompare([]byte(want), []byte(pinOf(key))) != 1 {
		return false, fmt.Errorf("%w (%s)", ErrSensorMismatch, path)
	}
	return false, nil
}

// Entry is one finger fpd enrolled.
type Entry struct {
	UID     uint32
	Subtype uint16
	Record  uint16 // the finger record's id in the sensor's database
	TID     []byte // the template id the sensor reports on a match
}

// Ledger is the list of fingers fpd enrolled. Each change is written
// through at once.
type Ledger struct {
	path    string
	entries []Entry
}

const ledgerHeader = "# fpd enrollment ledger: uid finger record tid (hex). Written by fpd.\n"

// LoadLedger reads the ledger. exists is false when there is no file yet:
// the caller then adopts the sensor's current enrollments.
func LoadLedger(path string) (l *Ledger, exists bool, err error) {
	l = &Ledger{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseEntry(line)
		if err != nil {
			return nil, false, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		l.entries = append(l.entries, e)
	}
	return l, true, nil
}

func parseEntry(line string) (Entry, error) {
	f := strings.Fields(line)
	if len(f) != 4 {
		return Entry{}, fmt.Errorf("%d fields, want 4", len(f))
	}
	uid, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return Entry{}, err
	}
	sub, err := strconv.ParseUint(f[1], 10, 16)
	if err != nil {
		return Entry{}, err
	}
	rec, err := strconv.ParseUint(f[2], 10, 16)
	if err != nil {
		return Entry{}, err
	}
	tid, err := hex.DecodeString(f[3])
	if err != nil || len(tid) == 0 {
		return Entry{}, fmt.Errorf("bad tid %q", f[3])
	}
	return Entry{UID: uint32(uid), Subtype: uint16(sub), Record: uint16(rec), TID: tid}, nil
}

func (l *Ledger) save() error {
	var b strings.Builder
	b.WriteString(ledgerHeader)
	for _, e := range l.entries {
		fmt.Fprintf(&b, "%d %d %d %s\n", e.UID, e.Subtype, e.Record, hex.EncodeToString(e.TID))
	}
	return atomicfile.Write(l.path, []byte(b.String()), 0o600)
}

// Replace sets the whole ledger, as adoption and a fresh pairing do.
func (l *Ledger) Replace(entries []Entry) error {
	l.entries = append([]Entry(nil), entries...)
	return l.save()
}

// Add records an enrollment, replacing one for the same user and finger.
func (l *Ledger) Add(e Entry) error {
	l.drop(func(x Entry) bool { return x.UID == e.UID && x.Subtype == e.Subtype })
	l.entries = append(l.entries, e)
	return l.save()
}

// Remove forgets a user's finger, or every finger of theirs for
// subtype 0.
func (l *Ledger) Remove(uid uint32, subtype uint16) error {
	l.drop(func(x Entry) bool { return x.UID == uid && (subtype == 0 || x.Subtype == subtype) })
	return l.save()
}

func (l *Ledger) drop(match func(Entry) bool) {
	kept := l.entries[:0]
	for _, e := range l.entries {
		if !match(e) {
			kept = append(kept, e)
		}
	}
	l.entries = kept
}

// Owner returns the entry whose template id is tid.
func (l *Ledger) Owner(tid []byte) (Entry, bool) {
	for _, e := range l.entries {
		if len(tid) > 0 && subtle.ConstantTimeCompare(e.TID, tid) == 1 {
			return e, true
		}
	}
	return Entry{}, false
}

// Entries returns a copy of the ledger.
func (l *Ledger) Entries() []Entry { return append([]Entry(nil), l.entries...) }
