// Package crosfptest is a simulated fingerprint MCU for tests: it answers
// the host commands crosfp sends the way the real MCU does, and raises
// events from scripted touches.
package crosfptest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"git.airies.net/vifair22/tp-fingerprint/internal/crosfp"
)

// Touch is one scripted finger on the sensor. Finger names whose print it
// is; Code, when not zero, makes the MCU reject the touch with that code
// instead.
type Touch struct {
	Finger string
	Code   uint32
}

// MCU is the simulation. Its fields may be set before use.
type MCU struct {
	mu sync.Mutex

	TemplateSize int
	TemplateMax  int
	Format       uint32
	// EnrollSteps is how many good touches an enrollment takes.
	EnrollSteps int
	// Touches are consumed by enroll images and matches, in order.
	Touches []Touch
	// Fail makes the command fail with the result.
	Fail map[uint32]crosfp.Result
	// FailOnce makes the command's next call fail with the result.
	FailOnce map[uint32]crosfp.Result
	// UpdateOnMatch makes the next match report a template update.
	UpdateOnMatch bool

	Seed      []byte
	SeedCalls int
	Context   []byte
	Templates [][]byte
	Mode      uint32
	Closed    bool

	upload   []byte
	enrolled int
	events   chan crosfp.Event
	ctxBusy  int
}

// New returns an MCU shaped like the C14's.
func New() *MCU {
	return &MCU{TemplateSize: 5156, TemplateMax: 5, Format: 4, EnrollSteps: 4,
		Fail: map[uint32]crosfp.Result{}, events: make(chan crosfp.Event, 64)}
}

// key is what "encrypts" a template: the seed and context it was made under.
func (m *MCU) key() []byte { return append(append([]byte{}, m.Seed...), m.Context...) }

func (m *MCU) blob(finger string) []byte {
	b := append(m.key(), []byte("print:"+finger+";")...)
	if len(b) < m.TemplateSize {
		b = append(b, make([]byte, m.TemplateSize-len(b))...)
	}
	return b[:m.TemplateSize]
}

func fingerOf(b []byte) string {
	i := bytes.Index(b, []byte("print:"))
	if i < 0 {
		return ""
	}
	j := bytes.IndexByte(b[i:], ';')
	if j < 0 {
		return ""
	}
	return string(b[i+6 : i+j])
}

func (m *MCU) push(e crosfp.Event) { m.events <- e }

func (m *MCU) nextTouch() (Touch, bool) {
	if len(m.Touches) == 0 {
		return Touch{}, false
	}
	t := m.Touches[0]
	m.Touches = m.Touches[1:]
	return t, true
}

// Command implements crosfp.Transport.
func (m *MCU) Command(cmd, version uint32, out []byte, insize int) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.Fail[cmd]; ok {
		return nil, r
	}
	if r, ok := m.FailOnce[cmd]; ok {
		delete(m.FailOnce, cmd)
		return nil, r
	}
	le := binary.LittleEndian
	switch cmd {
	case 0x000B: // protocol info: 600-byte packets
		r := make([]byte, 12)
		le.PutUint16(r[4:], 600)
		le.PutUint16(r[6:], 600)
		return r, nil
	case 0x0008:
		return []byte{2, 0, 0, 0}, nil
	case 0x0403:
		if version != 2 {
			return nil, crosfp.ResultInvalidVersion
		}
		r := make([]byte, 36)
		le.PutUint32(r[0:], 0x20435046)
		le.PutUint32(r[20:], uint32(m.TemplateSize))
		le.PutUint16(r[24:], uint16(m.TemplateMax))
		le.PutUint16(r[26:], uint16(len(m.Templates)))
		le.PutUint32(r[32:], m.Format)
		return r, nil
	case 0x0409:
		r := make([]byte, 8)
		le.PutUint32(r[0:], 1)
		if m.Seed != nil {
			le.PutUint32(r[4:], 1)
		}
		return r, nil
	case 0x0408:
		m.SeedCalls++
		if m.Seed != nil {
			return nil, crosfp.ResultAccessDenied
		}
		if le.Uint16(out) != uint16(m.Format) {
			return nil, crosfp.ResultInvalidParam
		}
		m.Seed = append([]byte{}, out[4:]...)
		return nil, nil
	case 0x0406:
		if version != 1 {
			return nil, crosfp.ResultInvalidVersion
		}
		if out[0] == 0 {
			m.Context = append([]byte{}, out[4:]...)
			m.Templates = nil
			m.ctxBusy = 2
			return nil, nil
		}
		if m.ctxBusy > 0 {
			m.ctxBusy--
			return nil, crosfp.ResultBusy
		}
		return nil, nil
	case 0x0402:
		mode := le.Uint32(out)
		if mode&(1<<31) == 0 {
			m.Mode = mode
			m.act()
		}
		r := make([]byte, 4)
		le.PutUint32(r, m.Mode)
		return r, nil
	case 0x0404:
		off := le.Uint32(out)
		size := int(le.Uint32(out[4:]))
		idx := int(off>>28) - 1
		at := int(off & 0x0FFFFFFF)
		if idx < 0 || idx >= len(m.Templates) || at+size > len(m.Templates[idx]) {
			return nil, crosfp.ResultInvalidParam
		}
		return append([]byte{}, m.Templates[idx][at:at+size]...), nil
	case 0x0405:
		off := int(le.Uint32(out))
		size := le.Uint32(out[4:])
		n := int(size &^ 0x80000000)
		if off != len(m.upload) || 8+n > len(out) {
			return nil, crosfp.ResultInvalidParam
		}
		m.upload = append(m.upload, out[8:8+n]...)
		if size&0x80000000 != 0 {
			b := m.upload
			m.upload = nil
			if !bytes.HasPrefix(b, m.key()) || len(m.Templates) >= m.TemplateMax {
				return nil, crosfp.ResultInvalidParam
			}
			m.Templates = append(m.Templates, b)
		}
		return nil, nil
	}
	return nil, crosfp.ResultInvalidCommand
}

// act raises the events the new mode leads to.
func (m *MCU) act() {
	switch {
	case m.Mode&crosfp.ModeFingerUp != 0:
		m.push(crosfp.EventFingerUp)
	case m.Mode&crosfp.ModeEnrollImage != 0:
		t, ok := m.nextTouch()
		if !ok {
			return
		}
		if t.Code != 0 {
			m.push(crosfp.EventEnroll | crosfp.Event(t.Code) | crosfp.Event(m.percent()<<4))
			return
		}
		m.enrolled++
		pct := m.percent()
		if m.enrolled >= m.EnrollSteps {
			m.Templates = append(m.Templates, m.blob(t.Finger))
			m.enrolled = 0
			m.Mode = 0
		}
		m.push(crosfp.EventEnroll | crosfp.Event(pct<<4))
	case m.Mode&crosfp.ModeMatch != 0:
		t, ok := m.nextTouch()
		if !ok {
			return
		}
		m.Mode = 0
		if t.Code != 0 {
			m.push(crosfp.EventMatch | crosfp.Event(t.Code))
			return
		}
		if len(m.Templates) == 0 {
			m.push(crosfp.EventMatch | crosfp.Event(crosfp.MatchNoTemplates))
			return
		}
		for i, b := range m.Templates {
			if fingerOf(b) == t.Finger {
				code := uint32(crosfp.MatchYes)
				if m.UpdateOnMatch {
					code = crosfp.MatchYesUpdated
					m.UpdateOnMatch = false
				}
				m.push(crosfp.EventMatch | crosfp.Event(code) | crosfp.Event(i<<12))
				return
			}
		}
		m.push(crosfp.EventMatch | crosfp.Event(crosfp.MatchNo))
	}
}

func (m *MCU) percent() int {
	if m.EnrollSteps == 0 {
		return 100
	}
	return m.enrolled * 100 / m.EnrollSteps
}

// NextEvent implements crosfp.Transport.
func (m *MCU) NextEvent(ctx context.Context) (crosfp.Event, error) {
	select {
	case e := <-m.events:
		return e, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Close implements crosfp.Transport.
func (m *MCU) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
	return nil
}

// Fingers lists the prints the MCU holds, in template order.
func (m *MCU) Fingers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, b := range m.Templates {
		out = append(out, fingerOf(b))
	}
	return out
}

// String is for test failures.
func (m *MCU) String() string { return fmt.Sprintf("mcu{templates %v mode %#x}", m.Fingers(), m.Mode) }
