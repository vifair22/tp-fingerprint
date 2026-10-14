// Package promptled flashes an LED while the sensor waits for a finger, so
// a reader with no light of its own (the C14's, under the power button)
// still shows when a touch will be read.
//
// It drives a kernel LED class device: the kernel's timer trigger
// (ledtrig-timer) does the flashing, and when no request is waiting the
// trigger that was active before is put back. On the C14 that is
// chromeos-auto, which hands the LED back to the EC, so its own on/off and
// suspend breathing carry on unchanged.
package promptled

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClassDir is where the kernel lists LED class devices.
const ClassDir = "/sys/class/leds"

// The flash: fast enough to read as "waiting for you", not a status blink.
const (
	DelayOn  = 100 * time.Millisecond
	DelayOff = 100 * time.Millisecond
)

const timerTrigger = "timer"

// LED is one LED class device that flashes while any request waits.
type LED struct {
	dir     string
	restore string
	log     *slog.Logger

	mu     sync.Mutex
	active int
}

// Open takes the LED at dir (a directory under ClassDir). restore is the
// trigger to put back when nothing is waiting; empty means the one active
// now. A timer trigger found active is taken as left behind by an fpd that
// died mid-request, so restore must then be named, and it is put back
// straight away.
func Open(dir, restore string, log *slog.Logger) (*LED, error) {
	cur, err := currentTrigger(dir)
	if err != nil {
		return nil, err
	}
	if restore == "" {
		if cur == timerTrigger {
			return nil, fmt.Errorf("%s is already flashing (a previous fpd's?); name the trigger to restore", dir)
		}
		restore = cur
	}
	l := &LED{dir: dir, restore: restore, log: log}
	if cur == timerTrigger {
		if err := l.write("trigger", restore); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// Path resolves an LED name, or a path, to its directory.
func Path(name string) string {
	if strings.ContainsRune(name, '/') {
		return name
	}
	return filepath.Join(ClassDir, name)
}

// Prompt wraps a request's prompt callback: the LED starts flashing when
// the sensor is ready for the finger, and done, which the caller defers,
// stops it when the request ends however it ends. A nil LED wraps nothing.
func (l *LED) Prompt(prompt func()) (wrapped, done func()) {
	if l == nil {
		return prompt, func() {}
	}
	var once sync.Once
	started := false
	wrapped = func() {
		once.Do(func() {
			started = true
			l.start()
		})
		prompt()
	}
	done = func() {
		// A request that never prompted (not enrolled, sensor gone)
		// must not stop another request's flashing.
		once.Do(func() {})
		if started {
			l.stop()
		}
	}
	return wrapped, done
}

// Flashing reports whether a request is waiting on the LED.
func (l *LED) Flashing() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active > 0
}

func (l *LED) start() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active++
	if l.active > 1 {
		return
	}
	if err := l.flash(); err != nil {
		l.log.Warn("cannot flash the prompt LED (is ledtrig-timer loaded?)", "led", l.dir, "err", err)
	}
}

func (l *LED) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == 0 {
		return
	}
	l.active--
	if l.active > 0 {
		return
	}
	if err := l.write("trigger", l.restore); err != nil {
		l.log.Warn("cannot restore the prompt LED's trigger", "led", l.dir, "trigger", l.restore, "err", err)
	}
}

// Restore puts the resting trigger back whatever is waiting, for shutdown.
func (l *LED) Restore() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = 0
	return l.write("trigger", l.restore)
}

// flash selects the timer trigger, which creates delay_on and delay_off,
// then sets the rate.
func (l *LED) flash() error {
	if err := l.write("trigger", timerTrigger); err != nil {
		return err
	}
	if err := l.write("delay_on", strconv.FormatInt(DelayOn.Milliseconds(), 10)); err != nil {
		return err
	}
	return l.write("delay_off", strconv.FormatInt(DelayOff.Milliseconds(), 10))
}

func (l *LED) write(attr, value string) error {
	f, err := os.OpenFile(filepath.Join(l.dir, attr), os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(value)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// currentTrigger reads the bracketed name from the trigger attribute,
// which lists every trigger with the active one as "[name]".
func currentTrigger(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "trigger"))
	if err != nil {
		return "", err
	}
	for _, t := range strings.Fields(string(b)) {
		if len(t) > 2 && t[0] == '[' && t[len(t)-1] == ']' {
			return t[1 : len(t)-1], nil
		}
	}
	return "", errors.New(dir + ": no active trigger in its trigger list")
}
