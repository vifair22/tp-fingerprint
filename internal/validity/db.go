package validity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The sensor keeps its own database of records in flash partition 4. Each
// record has an id, a type, a storage id, a value and children. The
// Windows driver's layout, which the reference follows, is one storage
// record named "StgWindsor" holding user records (keyed by a Windows SID),
// each holding finger records whose value carries the template id. The
// templates themselves never leave the sensor.

// Record types.
const (
	recStorage = 4
	recUser    = 5
	recFinger  = 6
	// Asked for when creating a finger; the sensor stores it as recFinger
	// ("because of the magical db_write_enable").
	recFingerCreate = 0xb
	recData         = 8
)

// statusNotFound answers a storage or user lookup with no match.
const statusNotFound Status = 0x04b3

// StorageName is the storage record the Windows driver, and so the
// reference, keeps users under.
const StorageName = "StgWindsor"

// ErrNoStorage means the database has no StgWindsor storage yet: nothing
// has been enrolled.
var ErrNoStorage = errors.New("sensor database has no user storage yet")

// SID is a Windows security identifier, the key the sensor's user records
// are stored under.
type SID struct {
	Revision uint8
	Auth     uint64 // 48 bits
	SubAuth  []uint32
}

// sidPrefix is the reference's default mapping from a uid: a fixed
// domain, with the uid as the last sub-authority.
var sidPrefix = []uint32{21, 111111111, 1111111111, 1111111111}

// UIDSID returns the SID a Linux uid is stored under, as the reference
// maps it: S-1-5-21-111111111-1111111111-1111111111-<uid>.
func UIDSID(uid uint32) SID {
	return SID{Revision: 1, Auth: 5, SubAuth: append(append([]uint32(nil), sidPrefix...), uid)}
}

// UID returns the uid a SID made by UIDSID carries.
func (s SID) UID() (uint32, bool) {
	if s.Revision != 1 || s.Auth != 5 || len(s.SubAuth) != len(sidPrefix)+1 {
		return 0, false
	}
	for i, v := range sidPrefix {
		if s.SubAuth[i] != v {
			return 0, false
		}
	}
	return s.SubAuth[len(sidPrefix)], true
}

func (s SID) String() string {
	parts := []string{"S", strconv.Itoa(int(s.Revision)), strconv.FormatUint(s.Auth, 10)}
	for _, v := range s.SubAuth {
		parts = append(parts, strconv.FormatUint(uint64(v), 10))
	}
	return strings.Join(parts, "-")
}

// Bytes is the binary SID: revision, sub-authority count, the 48-bit
// authority big-endian, then the sub-authorities little-endian.
func (s SID) Bytes() []byte {
	b := []byte{s.Revision, byte(len(s.SubAuth))}
	b = binary.BigEndian.AppendUint16(b, uint16(s.Auth>>32))
	b = binary.BigEndian.AppendUint32(b, uint32(s.Auth))
	for _, v := range s.SubAuth {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

func parseSID(b []byte) (SID, error) {
	if len(b) < 8 || len(b) < 8+4*int(b[1]) {
		return SID{}, fmt.Errorf("sid: %d bytes: %w", len(b), ErrShortReply)
	}
	s := SID{Revision: b[0]}
	for _, c := range b[2:8] {
		s.Auth = s.Auth<<8 | uint64(c)
	}
	for i := range int(b[1]) {
		s.SubAuth = append(s.SubAuth, binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}

// identityMinLen is the size of the Windows union an identity is stored
// in; the reference pads to it because a lookup treats the same SID at a
// different length as a different key.
const identityMinLen = 0x4c

func identityBytes(s SID) []byte {
	sid := s.Bytes()
	b := binary.LittleEndian.AppendUint32(nil, 3) // identity type: SID
	b = binary.LittleEndian.AppendUint32(b, uint32(len(sid)))
	b = append(b, sid...)
	for len(b) < identityMinLen {
		b = append(b, 0)
	}
	return b
}

func parseIdentity(b []byte) (SID, error) {
	if len(b) < 8 {
		return SID{}, fmt.Errorf("identity: %d bytes: %w", len(b), ErrShortReply)
	}
	if t := binary.LittleEndian.Uint32(b); t != 3 {
		return SID{}, fmt.Errorf("identity type %d is not a SID", t)
	}
	n := int(binary.LittleEndian.Uint32(b[4:]))
	if len(b)-8 < n {
		return SID{}, fmt.Errorf("identity: %d-byte SID in %d bytes: %w", n, len(b)-8, ErrShortReply)
	}
	return parseSID(b[8 : 8+n])
}

// RecordRef is a child entry: a record id and its value size or type.
type RecordRef struct {
	ID   uint16
	Size uint16
}

// Storage is a storage record and the users under it.
type Storage struct {
	ID    uint16
	Name  string
	Users []RecordRef
}

// Finger is one enrolled finger of a user.
type Finger struct {
	ID      uint16
	Subtype uint16 // the finger, see FingerName
	Storage uint16
	Size    uint16
}

// User is a user record.
type User struct {
	ID      uint16
	SID     SID
	Fingers []Finger
}

// DBInfo is the reply to command 0x45.
type DBInfo struct {
	Total   uint32 // partition size
	Used    uint32 // not deleted
	Free    uint32 // unallocated
	Records uint16 // including deleted
	Roots   []uint16
}

// DB runs database commands over a session.
type DB struct{ c Commander }

// NewDB returns a DB over c, normally an open Session.
func NewDB(c Commander) *DB { return &DB{c} }

// Info runs command 0x45.
func (d *DB) Info() (*DBInfo, error) {
	p, err := d.c.CmdOK([]byte{0x45})
	if err != nil {
		return nil, err
	}
	if len(p) < 0x18 {
		return nil, fmt.Errorf("db info: %d bytes: %w", len(p), ErrShortReply)
	}
	info := &DBInfo{
		Total:   binary.LittleEndian.Uint32(p[8:]),
		Used:    binary.LittleEndian.Uint32(p[12:]),
		Free:    binary.LittleEndian.Uint32(p[16:]),
		Records: binary.LittleEndian.Uint16(p[20:]),
	}
	n := int(binary.LittleEndian.Uint16(p[22:]))
	if len(p)-0x18 < 2*n {
		return nil, fmt.Errorf("db info: %d roots in %d bytes: %w", n, len(p)-0x18, ErrShortReply)
	}
	for i := range n {
		info.Roots = append(info.Roots, binary.LittleEndian.Uint16(p[0x18+2*i:]))
	}
	return info, nil
}

// Storage looks up the StgWindsor storage (command 0x4b). It returns
// ErrNoStorage when there is none.
func (d *DB) Storage() (*Storage, error) {
	name := append([]byte(StorageName), 0)
	req := []byte{0x4b, 0, 0}
	req = binary.LittleEndian.AppendUint16(req, uint16(len(name)))
	st, p, err := d.c.Cmd(append(req, name...))
	if err != nil {
		return nil, err
	}
	switch st {
	case StatusOK:
	case statusNotFound:
		return nil, ErrNoStorage
	default:
		return nil, &StatusError{Cmd: 0x4b, Status: st}
	}
	if len(p) < 8 {
		return nil, fmt.Errorf("storage: %d bytes: %w", len(p), ErrShortReply)
	}
	s := &Storage{ID: binary.LittleEndian.Uint16(p)}
	users := int(binary.LittleEndian.Uint16(p[2:]))
	nameLen := int(binary.LittleEndian.Uint16(p[4:]))
	p = p[8:]
	if len(p) != 4*users+nameLen {
		return nil, fmt.Errorf("storage: %d bytes for %d users and a %d-byte name", len(p), users, nameLen)
	}
	for i := range users {
		s.Users = append(s.Users, RecordRef{binary.LittleEndian.Uint16(p[4*i:]), binary.LittleEndian.Uint16(p[4*i+2:])})
	}
	s.Name = string(bytes.TrimRight(p[4*users:], "\x00"))
	return s, nil
}

// User reads a user record by id (command 0x4a).
func (d *DB) User(id uint16) (*User, error) {
	req := []byte{0x4a}
	req = binary.LittleEndian.AppendUint16(req, id)
	req = append(req, 0, 0, 0, 0)
	p, err := d.c.CmdOK(req)
	if err != nil {
		return nil, err
	}
	return parseUser(p)
}

// LookupUser finds the user stored under sid in storage, or nil.
func (d *DB) LookupUser(storage uint16, sid SID) (*User, error) {
	id := identityBytes(sid)
	req := []byte{0x4a, 0, 0}
	req = binary.LittleEndian.AppendUint16(req, storage)
	req = binary.LittleEndian.AppendUint16(req, uint16(len(id)))
	st, p, err := d.c.Cmd(append(req, id...))
	if err != nil {
		return nil, err
	}
	switch st {
	case StatusOK:
		return parseUser(p)
	case statusNotFound:
		return nil, nil
	}
	return nil, &StatusError{Cmd: 0x4a, Status: st}
}

func parseUser(p []byte) (*User, error) {
	if len(p) < 8 {
		return nil, fmt.Errorf("user: %d bytes: %w", len(p), ErrShortReply)
	}
	u := &User{ID: binary.LittleEndian.Uint16(p)}
	fingers := int(binary.LittleEndian.Uint16(p[2:]))
	idLen := int(binary.LittleEndian.Uint16(p[6:]))
	p = p[8:]
	if len(p) != 8*fingers+idLen {
		return nil, fmt.Errorf("user: %d bytes for %d fingers and a %d-byte identity", len(p), fingers, idLen)
	}
	for i := range fingers {
		e := p[8*i:]
		u.Fingers = append(u.Fingers, Finger{
			ID:      binary.LittleEndian.Uint16(e),
			Subtype: binary.LittleEndian.Uint16(e[2:]),
			Storage: binary.LittleEndian.Uint16(e[4:]),
			Size:    binary.LittleEndian.Uint16(e[6:]),
		})
	}
	sid, err := parseIdentity(p[8*fingers:])
	if err != nil {
		return nil, err
	}
	u.SID = sid
	return u, nil
}

// Record is a record read by id.
type Record struct {
	ID, Type, Storage uint16
	Value             []byte
	Children          []RecordRef // Size holds the child's type
}

// RecordValue reads a record's value (command 0x49).
func (d *DB) RecordValue(id uint16) (*Record, error) {
	p, err := d.c.CmdOK(binary.LittleEndian.AppendUint16([]byte{0x49}, id))
	if err != nil {
		return nil, err
	}
	if len(p) < 10 {
		return nil, fmt.Errorf("record %d: %d bytes: %w", id, len(p), ErrShortReply)
	}
	r := parseRecordHeader(p)
	n := int(binary.LittleEndian.Uint16(p[6:]))
	if len(p)-10 < n {
		return nil, fmt.Errorf("record %d: %d-byte value in %d bytes: %w", id, n, len(p)-10, ErrShortReply)
	}
	r.Value = append([]byte(nil), p[10:10+n]...)
	return r, nil
}

// RecordChildren lists a record's children (command 0x46).
func (d *DB) RecordChildren(id uint16) (*Record, error) {
	p, err := d.c.CmdOK(binary.LittleEndian.AppendUint16([]byte{0x46}, id))
	if err != nil {
		return nil, err
	}
	if len(p) < 12 {
		return nil, fmt.Errorf("record %d: %d bytes: %w", id, len(p), ErrShortReply)
	}
	r := parseRecordHeader(p)
	n := int(binary.LittleEndian.Uint16(p[8:]))
	if len(p)-12 < 4*n {
		return nil, fmt.Errorf("record %d: %d children in %d bytes: %w", id, n, len(p)-12, ErrShortReply)
	}
	for i := range n {
		e := p[12+4*i:]
		r.Children = append(r.Children, RecordRef{binary.LittleEndian.Uint16(e), binary.LittleEndian.Uint16(e[2:])})
	}
	return r, nil
}

func parseRecordHeader(p []byte) *Record {
	return &Record{
		ID:      binary.LittleEndian.Uint16(p),
		Type:    binary.LittleEndian.Uint16(p[2:]),
		Storage: binary.LittleEndian.Uint16(p[4:]),
	}
}

// DeleteRecord deletes a record and, as the sensor implements it, its
// children (command 0x48).
func (d *DB) DeleteRecord(id uint16) error {
	_, err := d.c.CmdOK(binary.LittleEndian.AppendUint16([]byte{0x48}, id))
	return err
}

// newRecord creates a record (command 0x47) inside a flash transaction.
func (d *DB) newRecord(parent, typ, storage uint16, value []byte) (uint16, error) {
	// The reference reads the database info first, meaning to check free
	// space; it is kept for the same command sequence.
	if _, err := d.Info(); err != nil {
		return 0, err
	}
	if _, err := d.c.CmdOK(blobDBWriteEnable); err != nil {
		return 0, fmt.Errorf("write enable: %w", err)
	}
	req := []byte{0x47}
	for _, v := range []uint16{parent, typ, storage, uint16(len(value))} {
		req = binary.LittleEndian.AppendUint16(req, v)
	}
	var id uint16
	err := withCleanups(d.c, func() error {
		p, err := d.c.CmdOK(append(req, value...))
		if err != nil {
			return err
		}
		if len(p) < 2 {
			return fmt.Errorf("new record: %d-byte reply: %w", len(p), ErrShortReply)
		}
		id = binary.LittleEndian.Uint16(p)
		return nil
	})
	return id, err
}

// EnsureStorage returns the StgWindsor storage, creating it (under root
// record 1, storage 3, as the Windows driver does) when it is missing.
func (d *DB) EnsureStorage() (*Storage, error) {
	s, err := d.Storage()
	if !errors.Is(err, ErrNoStorage) {
		return s, err
	}
	if _, err := d.newRecord(1, recStorage, 3, append([]byte(StorageName), 0)); err != nil {
		return nil, fmt.Errorf("create storage: %w", err)
	}
	return d.Storage()
}

// NewUser creates a user record for sid in storage.
func (d *DB) NewUser(storage uint16, sid SID) (uint16, error) {
	return d.newRecord(storage, recUser, storage, identityBytes(sid))
}

// NewFinger creates a finger record for user from the data enrollment
// produced.
func (d *DB) NewFinger(storage, user uint16, data []byte) (uint16, error) {
	return d.newRecord(user, recFingerCreate, storage, data)
}

// Users reads every user in storage.
func (d *DB) Users(s *Storage) ([]*User, error) {
	var out []*User
	for _, r := range s.Users {
		u, err := d.User(r.ID)
		if err != nil {
			return nil, fmt.Errorf("user record %d: %w", r.ID, err)
		}
		out = append(out, u)
	}
	return out, nil
}

// Finger subtypes for the ten fingers, in fprintd's names; the numbering
// is the reference's (ANSI 381 positions).
var fingerNames = []string{
	1: "right-thumb", 2: "right-index-finger", 3: "right-middle-finger",
	4: "right-ring-finger", 5: "right-little-finger", 6: "left-thumb",
	7: "left-index-finger", 8: "left-middle-finger", 9: "left-ring-finger",
	10: "left-little-finger",
}

// FingerName names a subtype, or describes it if it is not one of the ten.
func FingerName(subtype uint16) string {
	if int(subtype) < len(fingerNames) && fingerNames[subtype] != "" {
		return fingerNames[subtype]
	}
	return fmt.Sprintf("subtype 0x%02x", subtype)
}

// FingerSubtype is the inverse of FingerName for the ten fingers.
func FingerSubtype(name string) (uint16, bool) {
	for i, n := range fingerNames {
		if n != "" && n == name {
			return uint16(i), true
		}
	}
	return 0, false
}
