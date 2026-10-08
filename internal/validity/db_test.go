package validity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// simDB is a record store answering the database commands the way the
// reference parses them.
type simDB struct {
	next    uint16
	records map[uint16]*simRecord
}

type simRecord struct {
	id, parent, typ, storage uint16
	value                    []byte
}

func (d *simDB) children(id uint16) []*simRecord {
	var out []*simRecord
	for i := uint16(1); i < d.next; i++ {
		if r, ok := d.records[i]; ok && r.parent == id {
			out = append(out, r)
		}
	}
	return out
}

func (d *simDB) remove(id uint16) {
	for _, c := range d.children(id) {
		d.remove(c.id)
	}
	delete(d.records, id)
}

func u16s(vs ...int) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint16(b, uint16(v))
	}
	return b
}

var notFound = []byte{0xb3, 0x04}

func (s *simSensor) dbCmd(req []byte) []byte {
	if s.db == nil {
		s.db = &simDB{next: 10, records: map[uint16]*simRecord{}}
	}
	d := s.db
	ok := []byte{0, 0}
	le := binary.LittleEndian
	switch req[0] {
	case 0x45:
		info := binary.LittleEndian.AppendUint32(nil, 1)
		info = binary.LittleEndian.AppendUint32(info, 0)
		for _, v := range []uint32{0x80000, uint32(len(d.records)) * 0x100, 0x70000} {
			info = binary.LittleEndian.AppendUint32(info, v)
		}
		return concat(ok, info, u16s(len(d.records), 1, 3))
	case 0x47:
		parent, typ, stg, n := le.Uint16(req[1:]), le.Uint16(req[3:]), le.Uint16(req[5:]), int(le.Uint16(req[7:]))
		if n != len(req)-9 {
			s.t.Errorf("sim: new record of %d bytes says %d", len(req)-9, n)
		}
		if typ == recFingerCreate {
			typ = recFinger
		}
		id := d.next
		d.next++
		d.records[id] = &simRecord{id, parent, typ, stg, append([]byte(nil), req[9:]...)}
		if typ == recFinger {
			// The sensor raises an interrupt once a finger is stored;
			// the reference waits for it.
			s.tls.ints = append(s.tls.ints, []byte{7, 0, 0})
		}
		return concat(ok, u16s(int(id)))
	case 0x48:
		id := le.Uint16(req[1:])
		if _, exists := d.records[id]; !exists {
			return notFound
		}
		d.remove(id)
		return ok
	case 0x49, 0x46:
		r, exists := d.records[le.Uint16(req[1:])]
		if !exists {
			return notFound
		}
		if req[0] == 0x49 {
			return concat(ok, u16s(int(r.id), int(r.typ), int(r.storage), len(r.value), 0), r.value)
		}
		kids := d.children(r.id)
		out := concat(ok, u16s(int(r.id), int(r.typ), int(r.storage), len(r.value), len(kids), 0))
		for _, k := range kids {
			out = append(out, u16s(int(k.id), int(k.typ))...)
		}
		return out
	case 0x4b:
		name := req[5:]
		for _, r := range d.records {
			if r.typ == recStorage && bytes.Equal(r.value, name) {
				var tab []byte
				users := d.children(r.id)
				for _, u := range users {
					tab = append(tab, u16s(int(u.id), len(u.value))...)
				}
				return concat(ok, u16s(int(r.id), len(users), len(r.value), 0), tab, r.value)
			}
		}
		return notFound
	case 0x4a:
		id, stg := le.Uint16(req[1:]), le.Uint16(req[3:])
		var u *simRecord
		if id != 0 {
			u = d.records[id]
		} else {
			ident := req[7:]
			for _, r := range d.children(stg) {
				if r.typ == recUser && bytes.Equal(r.value, ident) {
					u = r
				}
			}
		}
		if u == nil || u.typ != recUser {
			return notFound
		}
		var tab []byte
		fingers := d.children(u.id)
		for _, f := range fingers {
			tab = append(tab, u16s(int(f.id), int(le.Uint16(f.value)), int(f.storage), len(f.value))...)
		}
		return concat(ok, u16s(int(u.id), len(fingers), 0, len(u.value)), tab, u.value)
	}
	return []byte{1, 0}
}

func TestSIDs(t *testing.T) {
	sid := UIDSID(1000)
	if sid.String() != "S-1-5-21-111111111-1111111111-1111111111-1000" {
		t.Fatalf("sid %s", sid)
	}
	b := sid.Bytes()
	// What the reference's SidIdentity.to_bytes() gives for that SID.
	want := "010500000000000515000000c76b9f06c7353a42c7353a42e8030000"
	if hexOf(b) != want {
		t.Fatalf("bytes %s", hexOf(b))
	}
	back, err := parseSID(b)
	if err != nil || back.String() != sid.String() {
		t.Fatalf("round trip %s, %v", back, err)
	}
	if uid, ok := back.UID(); !ok || uid != 1000 {
		t.Fatalf("uid %d, %v", uid, ok)
	}
	for _, other := range []SID{
		{Revision: 1, Auth: 5, SubAuth: []uint32{18}},
		{Revision: 1, Auth: 5, SubAuth: []uint32{21, 1, 1111111111, 1111111111, 7}},
		{Revision: 2, Auth: 5, SubAuth: UIDSID(7).SubAuth},
	} {
		if _, ok := other.UID(); ok {
			t.Errorf("%s mapped to a uid", other)
		}
	}
	id := identityBytes(sid)
	if len(id) != identityMinLen {
		t.Fatalf("identity of %d bytes", len(id))
	}
	if got, err := parseIdentity(id); err != nil || got.String() != sid.String() {
		t.Fatalf("identity round trip %s, %v", got, err)
	}
	for name, b := range map[string][]byte{
		"short":       {3, 0, 0},
		"not a sid":   append([]byte{2, 0, 0, 0}, make([]byte, 8)...),
		"sid overrun": append(u16s(3, 0, 40, 0), 1, 5),
		"short sid":   append(u16s(3, 0, 4, 0), 1, 5, 0, 0),
	} {
		if _, err := parseIdentity(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestDBLifecycle(t *testing.T) {
	s, sess := pairedSim(t)
	d := NewDB(sess)

	if _, err := d.Storage(); !errors.Is(err, ErrNoStorage) {
		t.Fatalf("fresh database: %v", err)
	}
	stg, err := d.EnsureStorage()
	if err != nil || stg.Name != StorageName || len(stg.Users) != 0 {
		t.Fatalf("storage %+v, %v", stg, err)
	}
	if again, err := d.EnsureStorage(); err != nil || again.ID != stg.ID {
		t.Fatalf("second EnsureStorage: %+v, %v", again, err)
	}

	alice, bob := UIDSID(1000), UIDSID(1001)
	if u, err := d.LookupUser(stg.ID, alice); err != nil || u != nil {
		t.Fatalf("lookup before creation: %+v, %v", u, err)
	}
	uid, err := d.NewUser(stg.ID, alice)
	if err != nil {
		t.Fatal(err)
	}
	finger := concat(u16s(2, 3, 4, 0x20), []byte("template"))
	fid, err := d.NewFinger(stg.ID, uid, finger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.NewUser(stg.ID, bob); err != nil {
		t.Fatal(err)
	}

	u, err := d.LookupUser(stg.ID, alice)
	if err != nil || u == nil || u.ID != uid || len(u.Fingers) != 1 {
		t.Fatalf("lookup %+v, %v", u, err)
	}
	if f := u.Fingers[0]; f.ID != fid || f.Subtype != 2 || FingerName(f.Subtype) != "right-index-finger" {
		t.Fatalf("finger %+v", f)
	}
	stg, _ = d.Storage()
	users, err := d.Users(stg)
	if err != nil || len(users) != 2 {
		t.Fatalf("users %v, %v", users, err)
	}

	rec, err := d.RecordValue(fid)
	if err != nil || rec.Type != recFinger || !bytes.Equal(rec.Value, finger) {
		t.Fatalf("finger record %+v, %v", rec, err)
	}
	kids, err := d.RecordChildren(uid)
	if err != nil || len(kids.Children) != 1 || kids.Children[0].ID != fid {
		t.Fatalf("children %+v, %v", kids, err)
	}
	info, err := d.Info()
	if err != nil || info.Records != 4 || len(info.Roots) != 1 {
		t.Fatalf("info %+v, %v", info, err)
	}

	// Deleting a finger leaves the user; deleting the user removes it.
	if err := d.DeleteRecord(fid); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.LookupUser(stg.ID, alice); u == nil || len(u.Fingers) != 0 {
		t.Fatalf("after finger delete: %+v", u)
	}
	if err := d.DeleteRecord(uid); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.LookupUser(stg.ID, alice); u != nil {
		t.Fatal("user survived its deletion")
	}
	if err := d.DeleteRecord(uid); err == nil {
		t.Fatal("deleted a missing record")
	}

	// Each new record ran in a flash transaction.
	log := strings.Join(s.cmds, " ")
	if strings.Count(log, "tls:47") != 4 || strings.Count(log, "tls:write-enable tls:47") != 4 {
		t.Fatalf("record creation sequence: %s", log)
	}
}

func TestDBReplyErrors(t *testing.T) {
	tests := []struct {
		name string
		rsp  string
		run  func(d *DB) error
	}{
		{"info short", "0000 0100", func(d *DB) error { _, err := d.Info(); return err }},
		{"info roots overrun", "0000" + strings.Repeat("00", 22) + "0500",
			func(d *DB) error { _, err := d.Info(); return err }},
		{"storage status", "0100", func(d *DB) error { _, err := d.Storage(); return err }},
		{"storage short", "0000 0100", func(d *DB) error { _, err := d.Storage(); return err }},
		{"storage size mismatch", "0000 0100 0100 0000 0000", func(d *DB) error { _, err := d.Storage(); return err }},
		{"user short", "0000 01", func(d *DB) error { _, err := d.User(1); return err }},
		{"user size mismatch", "0000 0100 0100 0000 0000", func(d *DB) error { _, err := d.User(1); return err }},
		{"user lookup status", "0100", func(d *DB) error { _, err := d.LookupUser(1, UIDSID(1)); return err }},
		{"value short", "0000 0100", func(d *DB) error { _, err := d.RecordValue(1); return err }},
		{"value overrun", "0000 0100 0800 0300 0900 0000 01", func(d *DB) error { _, err := d.RecordValue(1); return err }},
		{"children short", "0000 0100", func(d *DB) error { _, err := d.RecordChildren(1); return err }},
		{"children overrun", "0000 0100 0800 0300 0000 0200 0000 0100", func(d *DB) error { _, err := d.RecordChildren(1); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeSensor{t: t, script: []exchange{{"", tt.rsp}}}
			l := NewLink(&anyReq{f}, nil)
			if err := tt.run(NewDB(l)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// anyReq answers whatever is sent with the next scripted reply, for tests
// about reply parsing rather than request layout.
type anyReq struct{ f *fakeSensor }

func (a *anyReq) Bulk(ep uint8, buf []byte, d time.Duration) (int, error) {
	if ep == epCmdOut && len(a.f.script) > 0 {
		a.f.script[0].req = hexOf(buf)
	}
	return a.f.Bulk(ep, buf, d)
}

func TestNewRecordFailures(t *testing.T) {
	for _, step := range []string{"tls:45", "tls:write-enable", "tls:47"} {
		t.Run(step, func(t *testing.T) {
			s, sess := pairedSim(t)
			s.fail = step
			if _, err := NewDB(sess).EnsureStorage(); err == nil {
				t.Fatal("created storage")
			}
		})
	}
}

func TestFingerNames(t *testing.T) {
	for i := uint16(1); i <= 10; i++ {
		n := FingerName(i)
		if back, ok := FingerSubtype(n); !ok || back != i {
			t.Errorf("%d: %s -> %d", i, n, back)
		}
	}
	if FingerName(0) != "subtype 0x00" || FingerName(0xf5) != "subtype 0xf5" {
		t.Error("unnamed subtypes")
	}
	if _, ok := FingerSubtype("nose"); ok {
		t.Error("nose is not a finger")
	}
}
