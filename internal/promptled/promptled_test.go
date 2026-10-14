package promptled

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLED makes a directory that stands in for an LED class device. The
// kernel's trigger attribute reads as a list and takes one name; a plain
// file only echoes what was last written, which is what the tests check.
func fakeLED(t *testing.T, trigger string) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string]string{
		"trigger": trigger, "delay_on": "500", "delay_off": "500",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, dir, attr string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, attr))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestOpenRemembersActiveTrigger(t *testing.T) {
	dir := fakeLED(t, "none default [chromeos-auto] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	if l.restore != "chromeos-auto" {
		t.Fatalf("restore = %q", l.restore)
	}
}

func TestOpenLeftFlashing(t *testing.T) {
	dir := fakeLED(t, "none [timer] chromeos-auto\n")
	if _, err := Open(dir, "", quiet()); err == nil {
		t.Fatal("opened a flashing LED with nothing to restore")
	}
	if _, err := Open(dir, "chromeos-auto", quiet()); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "trigger"); got != "chromeos-auto" {
		t.Fatalf("trigger = %q, want the named one put back", got)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "absent"), "", quiet()); err == nil {
		t.Fatal("opened a missing LED")
	}
	if _, err := Open(fakeLED(t, "none timer\n"), "", quiet()); err == nil {
		t.Fatal("opened an LED with no active trigger")
	}
}

func TestPromptFlashesUntilDone(t *testing.T) {
	dir := fakeLED(t, "none [chromeos-auto] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	prompted := 0
	p, done := l.Prompt(func() { prompted++ })
	if l.Flashing() {
		t.Fatal("flashing before the prompt")
	}
	p()
	p() // a second prompt in the same request starts nothing new
	if prompted != 2 {
		t.Fatalf("prompt called %d times", prompted)
	}
	if !l.Flashing() || read(t, dir, "trigger") != "timer" {
		t.Fatal("not flashing after the prompt")
	}
	if read(t, dir, "delay_on") != "100" || read(t, dir, "delay_off") != "100" {
		t.Fatalf("rate %s/%s", read(t, dir, "delay_on"), read(t, dir, "delay_off"))
	}
	done()
	if l.Flashing() || read(t, dir, "trigger") != "chromeos-auto" {
		t.Fatal("still flashing after the request")
	}
}

func TestOverlappingRequests(t *testing.T) {
	dir := fakeLED(t, "[none] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	p1, done1 := l.Prompt(func() {})
	p2, done2 := l.Prompt(func() {})
	_, done3 := l.Prompt(func() {})
	p1()
	p2()
	done1()
	if read(t, dir, "trigger") != "timer" {
		t.Fatal("first request's end stopped the second's flashing")
	}
	done3() // never prompted: must not stop anything
	if !l.Flashing() {
		t.Fatal("an unprompted request stopped the flashing")
	}
	done2()
	if read(t, dir, "trigger") != "none" {
		t.Fatal("not restored after the last request")
	}
	l.stop() // nothing waiting: a no-op
	if l.Flashing() {
		t.Fatal("negative count")
	}
}

func TestNilLED(t *testing.T) {
	var l *LED
	called := false
	p, done := l.Prompt(func() { called = true })
	p()
	done()
	if !called {
		t.Fatal("nil LED dropped the prompt")
	}
	if err := l.Restore(); err != nil {
		t.Fatal(err)
	}
}

func TestRestore(t *testing.T) {
	dir := fakeLED(t, "[chromeos-auto] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := l.Prompt(func() {})
	p()
	if err := l.Restore(); err != nil {
		t.Fatal(err)
	}
	if l.Flashing() || read(t, dir, "trigger") != "chromeos-auto" {
		t.Fatal("Restore left it flashing")
	}
}

func TestWriteFailuresAreLogged(t *testing.T) {
	dir := fakeLED(t, "[chromeos-auto] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	l.log = slog.New(slog.NewTextHandler(&log, nil))
	for _, a := range []string{"delay_on", "delay_off"} {
		if err := os.Remove(filepath.Join(dir, a)); err != nil {
			t.Fatal(err)
		}
	}
	p, done := l.Prompt(func() {})
	p()
	if !strings.Contains(log.String(), "cannot flash") {
		t.Fatalf("no warning: %q", log.String())
	}
	if err := os.Remove(filepath.Join(dir, "trigger")); err != nil {
		t.Fatal(err)
	}
	done()
	if !strings.Contains(log.String(), "cannot restore") {
		t.Fatalf("no restore warning: %q", log.String())
	}
	if err := l.Restore(); err == nil {
		t.Fatal("Restore reported success with no trigger attribute")
	}
}

func TestDelayOffFailure(t *testing.T) {
	dir := fakeLED(t, "[none] timer\n")
	l, err := Open(dir, "", quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "delay_off")); err != nil {
		t.Fatal(err)
	}
	if err := l.flash(); err == nil {
		t.Fatal("flash succeeded without delay_off")
	}
}

func TestPath(t *testing.T) {
	if got := Path("chromeos:red:power"); got != "/sys/class/leds/chromeos:red:power" {
		t.Fatal(got)
	}
	if got := Path("/tmp/led"); got != "/tmp/led" {
		t.Fatal(got)
	}
}
