// Command fpd is the fingerprint daemon: it owns the T480's sensor and
// answers verification requests from pam_fpd.so, and enrollment and
// management requests from fpctl, on a unix socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/godbus/dbus/v5"

	"git.airies.net/vifair22/t480-fingerprint/internal/crosdev"
	"git.airies.net/vifair22/t480-fingerprint/internal/crosfp"
	"git.airies.net/vifair22/t480-fingerprint/internal/device"
	"git.airies.net/vifair22/t480-fingerprint/internal/fprint"
	"git.airies.net/vifair22/t480-fingerprint/internal/hostid"
	"git.airies.net/vifair22/t480-fingerprint/internal/proto"
	"git.airies.net/vifair22/t480-fingerprint/internal/server"
	"git.airies.net/vifair22/t480-fingerprint/internal/trust"
	"git.airies.net/vifair22/t480-fingerprint/internal/usbfs"
	"git.airies.net/vifair22/t480-fingerprint/internal/validity"
	"git.airies.net/vifair22/t480-fingerprint/internal/version"
)

const usage = `usage: fpd [--sensor auto|validity|crosfp] [--socket PATH] [--secret PATH] [--calib PATH] [--idle DURATION] [--no-dbus] [--debug]

Owns the fingerprint sensor and serves requests on a unix socket. Runs as
root; callers are authorised by their socket credentials.

  --sensor KIND   validity (the T480's Synaptics 06cb:009a), crosfp (a
                  ChromeOS fingerprint MCU, the C14's), or auto (default):
                  crosfp when ` + crosfp.DefaultPath + ` exists, else validity
  --socket PATH   where to listen (default ` + proto.DefaultSocket + `)
  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --calib PATH    calibration data (default /var/lib/fpd/calib-data.bin)
  --idle DURATION how long the sensor stays awake after a request before
                  USB may suspend it (default 30s); a suspended sensor
                  costs the next request a fresh session, about a second
  --no-dbus       do not serve fprintd's D-Bus API (System Settings enrollment)
  --debug         log every sensor command and reply
  --version       print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("fpd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sensor := fs.String("sensor", "auto", "")
	socket := fs.String("socket", proto.DefaultSocket, "")
	secret := fs.String("secret", hostid.DefaultPath, "")
	calib := fs.String("calib", "/var/lib/fpd/calib-data.bin", "")
	debug := fs.Bool("debug", false, "")
	idle := fs.Duration("idle", device.DefaultIdleGrace, "")
	noDBus := fs.Bool("no-dbus", false, "")
	showVersion := fs.Bool("version", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, usage)
			return 0
		}
		fmt.Fprintf(stderr, "fpd: bad arguments\n\n%s", usage)
		return 1
	}
	if *showVersion {
		fmt.Fprintf(stderr, "fpd %s\n", version.String())
		return 0
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	kind, err := chooseSensor(*sensor, crosdev.Present(crosfp.DefaultPath))
	if err != nil {
		fmt.Fprintf(stderr, "fpd: %v\n\n%s", err, usage)
		return 1
	}
	var dev reader
	switch kind {
	case "crosfp":
		dev = crosdev.New(crosdev.Config{SecretPath: *secret, Log: log})
	default:
		dev = device.New(device.Config{
			SecretPath: *secret, CalibPath: *calib, FwKey: validity.FirmwarePublicKey(),
			Bus: usbfs.System, Log: log, IdleGrace: *idle,
			PinPath: trust.DefaultPinPath, LedgerPath: trust.DefaultLedgerPath,
		})
	}
	log.Info("sensor", "kind", kind)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var bus busStarter
	if !*noDBus {
		bus = startFprint
	}
	if err := serve(ctx, log, *socket, dev, server.RemoteSession("/proc", "/run"), bus); err != nil {
		log.Error("fpd stopped", "err", err)
		return 1
	}
	return 0
}

// chooseSensor resolves --sensor: auto picks a fingerprint MCU when one is
// present, since a machine has one sensor or the other.
func chooseSensor(flagValue string, crosPresent bool) (string, error) {
	switch flagValue {
	case "validity", "crosfp":
		return flagValue, nil
	case "auto":
		if crosPresent {
			return "crosfp", nil
		}
		return "validity", nil
	}
	return "", fmt.Errorf("unknown sensor %q", flagValue)
}

// reader is the device as fpd drives it.
type reader interface {
	server.Reader
	Warm() error
	Close() error
}

// serve listens on socket and serves until ctx ends, then shuts the
// sensor down.
// busStarter starts the fprintd D-Bus API over the server's sensor and
// returns how to stop it.
type busStarter func(log *slog.Logger, r server.Reader, s *server.Server) (stop func())

// startFprint serves fprintd's API on the system bus for System Settings.
// fpd runs without it if the bus or the name is unavailable: PAM goes
// through the socket and does not need it.
func startFprint(log *slog.Logger, r server.Reader, s *server.Server) func() {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Warn("not serving the fprintd D-Bus API", "err", err)
		return func() {}
	}
	svc := fprint.New(conn, r, s, log, lookupUID)
	if err := svc.Start(); err != nil {
		log.Warn("not serving the fprintd D-Bus API", "err", err)
		conn.Close()
		return func() {}
	}
	log.Info("serving the fprintd D-Bus API", "name", fprint.BusName)
	return func() {
		svc.Close()
		conn.Close()
	}
}

func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(uid), err
}

func serve(ctx context.Context, log *slog.Logger, socket string, r reader, remote func(int32) bool, bus busStarter) error {
	ln, err := listen(socket)
	if err != nil {
		return err
	}
	log.Info("fpd listening", "socket", socket, "version", version.String())
	if err := r.Warm(); err != nil {
		// Not fatal: the sensor may come later (fpctl pair, a USB
		// glitch), and every request tries again.
		log.Warn("sensor not ready", "err", err)
	}
	s := server.New(r, log, remote)
	if bus != nil {
		stop := bus(log, r, s)
		defer stop()
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	err = s.Serve(ctx, ln)
	if cerr := r.Close(); cerr != nil {
		log.Warn("rebooting the sensor on the way out", "err", cerr)
	}
	_ = os.Remove(socket)
	log.Info("fpd stopped")
	return err
}

// listen creates the socket, replacing a stale one from an earlier run
// but nothing else, and lets anyone connect: who may do what is decided
// per request from the caller's credentials.
func listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
