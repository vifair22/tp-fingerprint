// Package crosdev is fpd's reader for a ChromeOS fingerprint MCU
// (internal/crosfp), the C14 Chromebook's sensor. It implements
// server.Reader over the MCU's own enroll and match.
//
// The MCU holds one user context at a time, and setting it clears every
// template it holds. So fpd sets a single context of its own, derived from
// the host secret, and keeps who owns which template on the host: each
// enrolled finger is one file under the store, holding the MCU's encrypted
// template. After every MCU reset, and after any change to the set, the
// context is set again and the templates uploaded in a fixed order, so the
// MCU's template index says whose finger matched.
//
// The seed the MCU derives its template key from comes from the host
// secret too. The MCU takes one seed per boot: fpd sets it if the MCU has
// none, and otherwise trusts that the seed is its own (a restarted fpd).
// A seed set by anyone else makes every stored template fail to load,
// which is reported, not repaired.
package crosdev

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/atomicfile"
	"git.airies.net/vifair22/t480-fingerprint/internal/crosfp"
	"git.airies.net/vifair22/t480-fingerprint/internal/hostid"
	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
)

// DefaultStore is where the encrypted templates live.
const DefaultStore = "/var/lib/fpd/crosfp"

// Errors for an unusable touch during enrollment, passed to progress.
var (
	ErrLowQuality  = errors.New("touch rejected: low image quality")
	ErrImmobile    = errors.New("touch rejected: finger did not move between touches")
	ErrLowCoverage = errors.New("touch rejected: too little of the finger on the sensor")
	// ErrFull is returned by Enroll when every template slot is in use.
	ErrFull = errors.New("every fingerprint slot on the sensor is in use")
	// ErrFormat is returned when the MCU's template format is not the one
	// this package was written against.
	ErrFormat = errors.New("unsupported template format")
)

// How long Verify and Identify wait for the finger to lift after a
// result, so one touch does not count twice.
const fingerUpGrace = 3 * time.Second

// Config says where the state lives and how to reach the MCU.
type Config struct {
	Path       string
	SecretPath string
	StoreDir   string
	Log        *slog.Logger
	// Open overrides how the MCU is reached (tests).
	Open func(path string) (crosfp.Transport, error)
}

// slot is one stored template and the finger it belongs to.
type slot struct {
	server.Enrolled
	file string
}

// Device implements fpd's reader over the MCU.
type Device struct {
	cfg    Config
	mu     sync.Mutex
	mcu    *crosfp.MCU
	info   crosfp.Info
	loaded []slot // index i is the MCU's template i
	fresh  bool   // loaded matches the store
	// secretContext is the user context fpd sets on the MCU.
	secretContext [crosfp.UserIDSize]byte
}

// New returns a Device; nothing is opened until the first request.
func New(cfg Config) *Device {
	if cfg.Path == "" {
		cfg.Path = crosfp.DefaultPath
	}
	if cfg.SecretPath == "" {
		cfg.SecretPath = hostid.DefaultPath
	}
	if cfg.StoreDir == "" {
		cfg.StoreDir = DefaultStore
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Open == nil {
		cfg.Open = func(p string) (crosfp.Transport, error) { return crosfp.Open(p) }
	}
	return &Device{cfg: cfg}
}

// Present reports whether path is a fingerprint MCU's device node, for
// choosing a backend.
func Present(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// derive is the HMAC of label under the host secret.
func derive(secret []byte, label string) [32]byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(label))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// open brings the MCU up: the seed if it has none, then the templates.
func (d *Device) open(ctx context.Context) error {
	if d.mcu != nil && d.fresh {
		return nil
	}
	if d.mcu == nil {
		t, err := d.cfg.Open(d.cfg.Path)
		if err != nil {
			return fmt.Errorf("%w: %v", server.ErrUnavailable, err)
		}
		m := crosfp.New(t)
		info, err := m.Info()
		if err != nil {
			t.Close()
			return fmt.Errorf("%w: reading the sensor: %v", server.ErrUnavailable, err)
		}
		if info.TemplateVersion != crosfp.TemplateFormat {
			t.Close()
			return fmt.Errorf("%w: the MCU uses format %d, fpd knows %d", ErrFormat, info.TemplateVersion, crosfp.TemplateFormat)
		}
		secret, created, err := hostid.LoadOrCreate(d.cfg.SecretPath)
		if err != nil {
			t.Close()
			return err
		}
		if created {
			d.cfg.Log.Info("created the host secret", "path", d.cfg.SecretPath)
		}
		set, err := m.SeedSet()
		if err != nil {
			t.Close()
			return fmt.Errorf("%w: %v", server.ErrUnavailable, err)
		}
		if !set {
			if err := m.SetSeed(derive(secret, "fpd crosfp seed v1")); err != nil {
				t.Close()
				return fmt.Errorf("setting the seed: %w", err)
			}
			d.cfg.Log.Info("set the fingerprint MCU's seed")
		}
		d.mcu, d.info = m, info
		d.fresh = false
		d.secretContext = derive(secret, "fpd crosfp context v1")
	}
	return d.reload(ctx)
}

// reload sets the context, which clears the MCU, and uploads the store.
func (d *Device) reload(ctx context.Context) error {
	slots, err := d.stored()
	if err != nil {
		return err
	}
	if err := d.mcu.SetContext(ctx, d.secretContext); err != nil {
		return d.fail(fmt.Errorf("setting the context: %w", err))
	}
	d.loaded = d.loaded[:0]
	for _, s := range slots {
		blob, err := os.ReadFile(s.file)
		if err != nil {
			return err
		}
		if err := d.mcu.UploadTemplate(blob); err != nil {
			// A template the MCU cannot decrypt (another seed, a corrupt
			// file) is left in the store and reported, not deleted.
			return d.fail(fmt.Errorf("loading %s: %w", filepath.Base(s.file), err))
		}
		d.loaded = append(d.loaded, s)
	}
	d.fresh = true
	return nil
}

// fail drops the MCU so the next request starts over, and returns err.
func (d *Device) fail(err error) error {
	if d.mcu != nil {
		d.mcu.Transport().Close()
		d.mcu = nil
	}
	d.fresh = false
	return err
}

// stored lists the store's templates in upload order.
func (d *Device) stored() ([]slot, error) {
	ents, err := os.ReadDir(d.cfg.StoreDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []slot
	for _, e := range ents {
		uid, sub, ok := parseName(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		out = append(out, slot{server.Enrolled{UID: uid, Subtype: sub}, filepath.Join(d.cfg.StoreDir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UID != out[j].UID {
			return out[i].UID < out[j].UID
		}
		return out[i].Subtype < out[j].Subtype
	})
	return out, nil
}

func fileName(uid uint32, sub uint16) string { return fmt.Sprintf("%d-%d.tpl", uid, sub) }

func parseName(name string) (uint32, uint16, bool) {
	base, ok := strings.CutSuffix(name, ".tpl")
	if !ok {
		return 0, 0, false
	}
	u, s, ok := strings.Cut(base, "-")
	if !ok {
		return 0, 0, false
	}
	uid, err1 := strconv.ParseUint(u, 10, 32)
	sub, err2 := strconv.ParseUint(s, 10, 16)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uint32(uid), uint16(sub), true
}

func (d *Device) owns(uid uint32) bool {
	for _, s := range d.loaded {
		if s.UID == uid {
			return true
		}
	}
	return false
}

// match runs one match: the touch's template index, or -1 for no match.
// retry is called for each unusable touch, which is tried again.
func (d *Device) match(ctx context.Context, retry func()) (int, error) {
	defer d.idle()
	for {
		if _, err := d.mcu.SetMode(crosfp.ModeMatch); err != nil {
			return -1, d.fail(fmt.Errorf("%w: %v", server.ErrUnavailable, err))
		}
		e, err := d.mcu.Wait(ctx, crosfp.EventMatch)
		if err != nil {
			return -1, err
		}
		switch e.Code() {
		case crosfp.MatchYes, crosfp.MatchYesUpdated, crosfp.MatchYesUpdateFail:
			idx := e.MatchIndex()
			if e.Code() == crosfp.MatchYesUpdated {
				d.saveUpdated(idx)
			}
			d.liftFinger(ctx)
			if idx >= len(d.loaded) {
				return -1, fmt.Errorf("the MCU matched template %d, fpd loaded %d", idx, len(d.loaded))
			}
			return idx, nil
		case crosfp.MatchNoLowQuality, crosfp.MatchNoLowCoverage:
			retry()
			d.liftFinger(ctx)
		case crosfp.MatchNo:
			d.liftFinger(ctx)
			return -1, nil
		case crosfp.MatchNoTemplates:
			d.fresh = false
			return -1, server.ErrNotEnrolled
		default:
			return -1, fmt.Errorf("match failed on the MCU (code %d)", e.Code())
		}
	}
}

// saveUpdated stores template idx again after the MCU refined it on a
// match. Failing to is not fatal: the old template still matches.
func (d *Device) saveUpdated(idx int) {
	if idx >= len(d.loaded) {
		return
	}
	blob, err := d.mcu.ReadTemplate(idx, int(d.info.TemplateSize))
	if err == nil {
		err = atomicfile.Write(d.loaded[idx].file, blob, 0o600)
	}
	if err != nil {
		d.cfg.Log.Warn("keeping the old template after the MCU updated it", "err", err)
	}
}

// liftFinger waits, briefly, for the finger to come off the sensor.
func (d *Device) liftFinger(ctx context.Context) {
	if _, err := d.mcu.SetMode(crosfp.ModeFingerUp); err != nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, fingerUpGrace)
	defer cancel()
	_, _ = d.mcu.Wait(wctx, crosfp.EventFingerUp)
}

// idle takes the MCU out of any mode, so it sleeps between requests.
func (d *Device) idle() {
	if d.mcu != nil {
		_, _ = d.mcu.SetMode(0)
	}
}

// Verify implements server.Reader.
func (d *Device) Verify(ctx context.Context, uid uint32, prompt, retry func()) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.open(ctx); err != nil {
		return false, err
	}
	if !d.owns(uid) {
		return false, server.ErrNotEnrolled
	}
	prompt()
	idx, err := d.match(ctx, retry)
	if err != nil || idx < 0 {
		return false, err
	}
	return d.loaded[idx].UID == uid, nil
}

// Identify implements server.Reader.
func (d *Device) Identify(ctx context.Context, prompt, retry func()) (server.Enrolled, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.open(ctx); err != nil {
		return server.Enrolled{}, false, err
	}
	if len(d.loaded) == 0 {
		return server.Enrolled{}, false, server.ErrNotEnrolled
	}
	prompt()
	idx, err := d.match(ctx, retry)
	if err != nil || idx < 0 {
		return server.Enrolled{}, false, err
	}
	return d.loaded[idx].Enrolled, true, nil
}

// Enroll implements server.Reader.
func (d *Device) Enroll(ctx context.Context, uid uint32, subtype uint16, prompt func(), progress func(int, error)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.open(ctx); err != nil {
		return err
	}
	for _, s := range d.loaded {
		if s.UID == uid && s.Subtype == subtype {
			return server.ErrExists
		}
	}
	if len(d.loaded) >= int(d.info.TemplateMax) {
		return ErrFull
	}
	defer d.idle()
	prompt()
	touches := 0
	for {
		if _, err := d.mcu.SetMode(crosfp.ModeEnrollSession | crosfp.ModeEnrollImage); err != nil {
			return d.fail(fmt.Errorf("%w: %v", server.ErrUnavailable, err))
		}
		e, err := d.mcu.Wait(ctx, crosfp.EventEnroll)
		if err != nil {
			return err
		}
		switch e.Code() {
		case crosfp.EnrollOK:
			touches++
			progress(touches, nil)
		case crosfp.EnrollLowQuality:
			progress(touches, ErrLowQuality)
		case crosfp.EnrollImmobile:
			progress(touches, ErrImmobile)
		case crosfp.EnrollLowCoverage:
			progress(touches, ErrLowCoverage)
		default:
			return fmt.Errorf("enrollment failed on the MCU (code %d)", e.Code())
		}
		if e.Progress() >= 100 {
			break
		}
		// Between touches the finger must lift, or the MCU sees the same
		// touch again.
		if _, err := d.mcu.SetMode(crosfp.ModeEnrollSession | crosfp.ModeFingerUp); err != nil {
			return d.fail(fmt.Errorf("%w: %v", server.ErrUnavailable, err))
		}
		if _, err := d.mcu.Wait(ctx, crosfp.EventFingerUp); err != nil {
			return err
		}
	}
	info, err := d.mcu.Info()
	if err != nil {
		return d.fail(err)
	}
	idx := int(info.TemplateValid) - 1
	if idx != len(d.loaded) {
		d.fresh = false
		return fmt.Errorf("the MCU reports %d templates after enrolling, fpd expected %d", info.TemplateValid, len(d.loaded)+1)
	}
	blob, err := d.mcu.ReadTemplate(idx, int(info.TemplateSize))
	if err != nil {
		return d.fail(err)
	}
	if err := os.MkdirAll(d.cfg.StoreDir, 0o700); err != nil {
		return err
	}
	file := filepath.Join(d.cfg.StoreDir, fileName(uid, subtype))
	if err := atomicfile.Write(file, blob, 0o600); err != nil {
		return err
	}
	// The MCU appended the new template at idx, where loaded appends it
	// too, so the map still matches the MCU. The next reload sorts it into
	// the store's order.
	d.loaded = append(d.loaded, slot{server.Enrolled{UID: uid, Subtype: subtype}, file})
	return nil
}

// List implements server.Reader. It reads the store and needs no MCU.
func (d *Device) List(uid uint32) ([]server.Enrolled, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	slots, err := d.stored()
	if err != nil {
		return nil, err
	}
	var out []server.Enrolled
	for _, s := range slots {
		if uid == proto.AllUsers || s.UID == uid {
			out = append(out, s.Enrolled)
		}
	}
	return out, nil
}

// Delete implements server.Reader: one finger, or every finger of uid for
// subtype 0. The MCU is reloaded on the next request.
func (d *Device) Delete(uid uint32, subtype uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	slots, err := d.stored()
	if err != nil {
		return err
	}
	n := 0
	for _, s := range slots {
		if s.UID == uid && (subtype == 0 || s.Subtype == subtype) {
			if err := os.Remove(s.file); err != nil {
				return err
			}
			n++
		}
	}
	if n == 0 {
		return server.ErrNotEnrolled
	}
	d.fresh = false
	return nil
}

// Warm implements fpd's reader: bring the MCU up before the first request.
func (d *Device) Warm() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.open(context.Background())
}

// Close implements fpd's reader.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mcu == nil {
		return nil
	}
	d.idle()
	err := d.mcu.Transport().Close()
	d.mcu = nil
	d.fresh = false
	return err
}
