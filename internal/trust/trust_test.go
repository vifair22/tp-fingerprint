package trust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fpd", "sensor-pin")
	adopted, err := CheckPin(path, []byte("sensor A"))
	if err != nil || !adopted {
		t.Fatalf("first use: %v, %v", adopted, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", st.Mode().Perm())
	}
	if adopted, err := CheckPin(path, []byte("sensor A")); err != nil || adopted {
		t.Fatalf("same sensor: %v, %v", adopted, err)
	}
	if _, err := CheckPin(path, []byte("sensor B")); !errors.Is(err, ErrSensorMismatch) {
		t.Fatalf("another sensor: %v", err)
	}
	if err := WritePin(path, []byte("sensor B")); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckPin(path, []byte("sensor B")); err != nil {
		t.Fatalf("after re-pairing: %v", err)
	}
	if _, err := CheckPin(t.TempDir(), []byte("x")); err == nil {
		t.Fatal("read a directory as a pin")
	}
}

func TestLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled")
	l, exists, err := LoadLedger(path)
	if err != nil || exists {
		t.Fatalf("missing ledger: %v, %v", exists, err)
	}
	a := Entry{UID: 1000, Subtype: 2, Record: 5, TID: []byte{1, 2, 3}}
	b := Entry{UID: 1000, Subtype: 7, Record: 9, TID: []byte{4, 5, 6}}
	c := Entry{UID: 1001, Subtype: 2, Record: 12, TID: []byte{7, 8, 9}}
	for _, e := range []Entry{a, b, c} {
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	// Re-enrolling a finger replaces its entry.
	a2 := Entry{UID: 1000, Subtype: 2, Record: 15, TID: []byte{0xa}}
	if err := l.Add(a2); err != nil {
		t.Fatal(err)
	}

	l2, exists, err := LoadLedger(path)
	if err != nil || !exists || len(l2.Entries()) != 3 {
		t.Fatalf("reloaded: %v, %v, %v", l2.Entries(), exists, err)
	}
	if e, ok := l2.Owner([]byte{0xa}); !ok || e.Record != 15 {
		t.Fatalf("owner of the new tid: %+v %v", e, ok)
	}
	if _, ok := l2.Owner([]byte{1, 2, 3}); ok {
		t.Fatal("the replaced tid still has an owner")
	}
	if _, ok := l2.Owner(nil); ok {
		t.Fatal("an empty tid has an owner")
	}

	if err := l2.Remove(1000, 7); err != nil {
		t.Fatal(err)
	}
	if _, ok := l2.Owner([]byte{4, 5, 6}); ok {
		t.Fatal("removed finger still owned")
	}
	if err := l2.Remove(1000, 0); err != nil {
		t.Fatal(err)
	}
	if got := l2.Entries(); len(got) != 1 || got[0].UID != 1001 {
		t.Fatalf("after removing user 1000: %+v", got)
	}
	if err := l2.Replace(nil); err != nil {
		t.Fatal(err)
	}
	l3, exists, _ := LoadLedger(path)
	if !exists || len(l3.Entries()) != 0 {
		t.Fatalf("emptied ledger: %v %v", exists, l3.Entries())
	}
	if b, _ := os.ReadFile(path); !strings.HasPrefix(string(b), "# fpd enrollment ledger") {
		t.Fatalf("file %q", b)
	}
}

func TestLedgerErrors(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"fields":    "1000 2 5\n",
		"uid":       "x 2 5 aa\n",
		"finger":    "1000 x 5 aa\n",
		"record":    "1000 2 x aa\n",
		"tid":       "1000 2 5 zz\n",
		"empty tid": "1000 2 5 \"\"\n",
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("# header\n\n"+content), 0o600)
		if _, _, err := LoadLedger(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, _, err := LoadLedger(dir); err == nil {
		t.Error("loaded a directory")
	}
	// A ledger that cannot be written reports it.
	l := &Ledger{path: filepath.Join(dir, "fields", "under-a-file")}
	if err := l.Add(Entry{UID: 1, Subtype: 1, TID: []byte{1}}); err == nil {
		t.Error("saved under a regular file")
	}
}
