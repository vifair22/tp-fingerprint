// Command fpctl administers the T480 fingerprint sensor.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.airies.net/vifair22/tp-fingerprint/internal/atomicfile"
	"git.airies.net/vifair22/tp-fingerprint/internal/client"
	"git.airies.net/vifair22/tp-fingerprint/internal/fwfetch"
	"git.airies.net/vifair22/tp-fingerprint/internal/hostid"
	"git.airies.net/vifair22/tp-fingerprint/internal/proto"
	"git.airies.net/vifair22/tp-fingerprint/internal/trust"
	"git.airies.net/vifair22/tp-fingerprint/internal/usbfs"
	"git.airies.net/vifair22/tp-fingerprint/internal/validity"
	"git.airies.net/vifair22/tp-fingerprint/internal/version"
)

// sensor is an open sensor handle: something to run transfers over and to
// close afterwards.
type sensor interface {
	validity.Transport
	io.Closer
}

// env is what a command handler may touch. Tests replace open.
type env struct {
	stdout, stderr io.Writer
	// open finds and opens the sensor, returning a description of where
	// it was found for the report.
	open func() (sensor, string, error)
	// fwKey verifies the sensor's ECDH key; tests swap in their own.
	fwKey *ecdsa.PublicKey
	// installerSHA512 and firmwareSHA256 pin the driver package and the
	// file extracted from it; tests swap in their own.
	installerSHA512 string
	firmwareSHA256  string
	http            *http.Client
	// socket is fpd's; everyday commands go through it when fpd runs.
	socket string
	// pinPath and ledgerPath are the host's trust records.
	pinPath, ledgerPath string
}

type command struct {
	name    string
	summary string
	usage   string
	run     func(e *env, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"probe", "read the sensor's state without changing it", probeUsage, runProbe},
		{"pair", "format an unpaired sensor and pair it with this host", pairUsage, runPair},
		{"status", "open a paired sensor's encrypted session", statusUsage, runStatus},
		{"factory-reset", "wipe the sensor's pairing and enrolled prints", factoryResetUsage, runFactoryReset},
		{"fetch-firmware", "extract the sensor firmware from Lenovo's driver package", fetchFirmwareUsage, runFetchFirmware},
		{"upload-firmware", "write the firmware to a paired sensor", uploadFirmwareUsage, runUploadFirmware},
		{"calibrate", "calibrate the sensor and store the result", calibrateUsage, runCalibrate},
		{"list", "list enrolled users and fingers", listUsage, runList},
		{"enroll", "enroll a finger for a user", enrollUsage, runEnroll},
		{"identify", "scan a finger and say whose it is", identifyUsage, runIdentify},
		{"delete", "delete a user's enrolled fingers", deleteUsage, runDelete},
		{"version", "print the version", "usage: fpctl version\n", runVersion},
		{"help", "show help for a command", "usage: fpctl help [command]\n", runHelp},
	}
}

func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// usageError makes run print the active command's help after the message.
type usageError struct{ msg string }

func (u *usageError) Error() string { return u.msg }

func main() {
	e := &env{
		stdout: os.Stdout, stderr: os.Stderr, open: openSystemSensor,
		fwKey:           validity.FirmwarePublicKey(),
		installerSHA512: fwfetch.InstallerSHA512,
		firmwareSHA256:  fwfetch.FirmwareSHA256,
		http:            &http.Client{Timeout: 5 * time.Minute},
		socket:          proto.DefaultSocket,
		pinPath:         trust.DefaultPinPath,
		ledgerPath:      trust.DefaultLedgerPath,
	}
	os.Exit(run(e, os.Args[1:]))
}

func run(e *env, args []string) int {
	if len(args) == 0 {
		writeOverview(e.stderr)
		return 1
	}
	if args[0] == "-h" || args[0] == "--help" {
		writeOverview(e.stdout)
		return 0
	}
	cmd := lookup(args[0])
	if cmd == nil {
		fmt.Fprintf(e.stderr, "fpctl: unknown command %q\n\n", args[0])
		writeOverview(e.stderr)
		return 1
	}
	err := cmd.run(e, args[1:])
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(e.stdout, cmd.usage)
		return 0
	}
	fmt.Fprintf(e.stderr, "fpctl %s: %v\n", cmd.name, err)
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(e.stderr, "\n%s", cmd.usage)
	}
	return 1
}

func writeOverview(w io.Writer) {
	fmt.Fprint(w, "usage: fpctl <command> [options]\n\ncommands:\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}

// parseFlags parses args against fs, accepting no positionals.
func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &usageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return &usageError{fmt.Sprintf("unexpected argument %q", fs.Arg(0))}
	}
	return nil
}

func runVersion(e *env, args []string) error {
	if err := parseFlags(flag.NewFlagSet("version", flag.ContinueOnError), args); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "fpctl %s\n", version.String())
	return nil
}

func runHelp(e *env, args []string) error {
	switch len(args) {
	case 0:
		writeOverview(e.stdout)
		return nil
	case 1:
		cmd := lookup(args[0])
		if cmd == nil {
			return &usageError{fmt.Sprintf("unknown command %q", args[0])}
		}
		fmt.Fprint(e.stdout, cmd.usage)
		return nil
	}
	return &usageError{"too many arguments"}
}

const probeUsage = `usage: fpctl probe [--trace]

Reads flash layout, ROM version and firmware state using only the commands
the sensor accepts before any setup, and changes nothing on it. Safe on a
sensor of unknown history.

  --trace   log every command and reply in hex to stderr
`

func runProbe(e *env, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		r, err := validity.Probe(l)
		if err != nil {
			return err
		}
		writeReport(e.stdout, where, r)
		return nil
	})
}

func newLogger(w io.Writer, trace bool) *slog.Logger {
	level := slog.LevelInfo
	if trace {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// withSensor opens the sensor, runs fn over a link to it, and closes it
// whatever fn returned.
func withSensor(e *env, log *slog.Logger, fn func(l *validity.Link, where string) error) error {
	dev, where, err := e.open()
	if err != nil {
		return err
	}
	ferr := fn(validity.NewLink(dev, log), where)
	if cerr := dev.Close(); cerr != nil {
		log.Warn("closing sensor", "err", cerr)
	}
	return ferr
}

const pairUsage = `usage: fpctl pair [--secret PATH] [--trace]

Formats the sensor's flash and pairs it with this host, binding the pairing
to the host secret at PATH (created if absent, never replaced). Refuses a
sensor that already has a partition table: run fpctl factory-reset first
for those. If pairing fails after it has formatted the flash, the sensor is
left partitioned without keys, and fpctl factory-reset recovers it too. The sensor reboots at the end and reappears on the bus a moment
later; check the result with fpctl status.

The host secret must be backed up: without it the pairing cannot be
opened, and the only way back is a factory reset and re-enrolling.

  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runPair(e *env, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	secretPath := fs.String("secret", hostid.DefaultPath, "")
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		// Refuse before creating a secret that would then pair nothing.
		fi, err := validity.GetFlashInfo(l)
		if err != nil {
			return err
		}
		if len(fi.Partitions) > 0 {
			return validity.ErrAlreadyPartitioned
		}
		secret, created, err := hostid.LoadOrCreate(*secretPath)
		if err != nil {
			return err
		}
		if created {
			log.Info("created host secret; back it up", "path", *secretPath)
		}
		key, err := validity.Pair(l, validity.DeriveHostKeys(secret), e.fwKey)
		if err != nil {
			return err
		}
		// A new pairing: pin this sensor, and start a ledger that knows
		// nothing yet, since the sensor's database is empty.
		if err := trust.WritePin(e.pinPath, key); err != nil {
			return err
		}
		ledger, _, err := trust.LoadLedger(e.ledgerPath)
		if err != nil {
			return err
		}
		if err := ledger.Replace(nil); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "paired %s; the sensor is rebooting, check it with fpctl status\n", where)
		return nil
	})
}

const factoryResetUsage = `usage: fpctl factory-reset --yes [--trace]

Wipes the sensor's pairing and every print enrolled on it, and reboots it.
This is the recovery path for a sensor paired elsewhere or left half-paired;
afterwards it can be paired again with fpctl pair. The host secret is not
touched. Without --yes nothing is sent.

  --yes     confirm the wipe
  --trace   log every command and reply in hex to stderr
`

func runFactoryReset(e *env, args []string) error {
	fs := flag.NewFlagSet("factory-reset", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "")
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !*yes {
		return &usageError{"refusing to wipe the sensor without --yes"}
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		if err := validity.FactoryReset(l); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "reset %s; the sensor is rebooting\n", where)
		return nil
	})
}

// The firmware and calibration data live beside the host secret.
const (
	defaultFirmwarePath = "/var/lib/fpd/" + validity.FirmwareName
	defaultCalibPath    = "/var/lib/fpd/calib-data.bin"
)

const fetchFirmwareUsage = `usage: fpctl fetch-firmware [--installer PATH] [--out PATH] [--innoextract PATH]

Downloads Lenovo's driver package (` + fwfetch.InstallerURL + `),
checks it against the pinned SHA-512, extracts ` + validity.FirmwareName + `
with innoextract, checks that against its own pinned SHA-256, and installs
it at the output path. The firmware is
proprietary: it is fetched here and never redistributed.

  --installer PATH    use a local copy of the package instead of downloading
  --out PATH          where to install the firmware (default
                      ` + defaultFirmwarePath + `)
  --innoextract PATH  the innoextract to run (default: from PATH)
`

func runFetchFirmware(e *env, args []string) error {
	fs := flag.NewFlagSet("fetch-firmware", flag.ContinueOnError)
	installer := fs.String("installer", "", "")
	out := fs.String("out", defaultFirmwarePath, "")
	inno := fs.String("innoextract", "innoextract", "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ctx := context.Background()
	work, err := os.MkdirTemp("", "fpctl-firmware-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	if *installer == "" {
		fmt.Fprintf(e.stderr, "downloading %s\n", fwfetch.InstallerURL)
		if *installer, err = fwfetch.Download(ctx, e.http, fwfetch.InstallerURL, e.installerSHA512, work); err != nil {
			return err
		}
	} else if err := fwfetch.Verify(*installer, e.installerSHA512); err != nil {
		return err
	}
	fw, cleanup, err := fwfetch.Extract(ctx, *inno, *installer, validity.FirmwareName, work)
	if err != nil {
		return err
	}
	defer cleanup()
	data, err := os.ReadFile(fw)
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != e.firmwareSHA256 {
		return fmt.Errorf("extracted %s does not match the pinned SHA-256: got %x", validity.FirmwareName, sum)
	}
	if _, err := validity.ParseFwext(data); err != nil {
		return err
	}
	if err := fwfetch.Install(fw, *out); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "installed %s (%d bytes, sha256 matches the pin)\n", *out, len(data))
	return nil
}

const uploadFirmwareUsage = `usage: fpctl upload-firmware [--file PATH] [--secret PATH] [--trace]

Opens the paired sensor and writes the firmware extension to its firmware
partition, then reboots it. Does nothing if firmware is already loaded.

  --file PATH     the firmware (default ` + defaultFirmwarePath + `)
  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runUploadFirmware(e *env, args []string) error {
	fs := flag.NewFlagSet("upload-firmware", flag.ContinueOnError)
	file := fs.String("file", defaultFirmwarePath, "")
	secretPath := fs.String("secret", hostid.DefaultPath, "")
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("%w (run fpctl fetch-firmware first)", err)
	}
	fw, err := validity.ParseFwext(data)
	if err != nil {
		return err
	}
	secret, err := hostid.Load(*secretPath)
	if err != nil {
		return err
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		sess, err := openPaired(e, l, secret)
		if err != nil {
			return err
		}
		fi, err := validity.UploadFirmware(sess, fw)
		switch {
		case errors.Is(err, validity.ErrFirmwareLoaded):
			fmt.Fprintf(e.stdout, "firmware %d.%d (built %s) already loaded; nothing written\n",
				fi.Major, fi.Minor, unixDate(fi.BuildTime))
			return nil
		case err != nil:
			return err
		}
		fmt.Fprintf(e.stdout, "loaded firmware %d.%d (built %s, %d modules) on %s; the sensor is rebooting\n",
			fi.Major, fi.Minor, unixDate(fi.BuildTime), len(fi.Modules), where)
		return nil
	})
}

const calibrateUsage = `usage: fpctl calibrate [--force] [--calib PATH] [--secret PATH] [--trace]

Opens the sensor and calibrates it if needed: when the saved calibration
data exists and the sensor's calibration partition holds a valid blank
image, nothing is done. Otherwise it runs three calibration captures and a
blank capture (keep fingers off the sensor), writes the blank image to the
sensor's calibration partition, and saves the calibration data.

  --force         recalibrate from scratch even if nothing is missing
  --calib PATH    calibration data (default ` + defaultCalibPath + `)
  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runCalibrate(e *env, args []string) error {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	force := fs.Bool("force", false, "")
	calibPath := fs.String("calib", defaultCalibPath, "")
	secretPath := fs.String("secret", hostid.DefaultPath, "")
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	secret, err := hostid.Load(*secretPath)
	if err != nil {
		return err
	}
	saved, err := os.ReadFile(*calibPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		sess, err := openPaired(e, l, secret)
		if err != nil {
			return err
		}
		sen, err := validity.OpenSensor(sess, saved)
		if err != nil {
			return err
		}
		did, err := sen.Calibrate(context.Background(), *force)
		if err != nil {
			return err
		}
		if !did {
			fmt.Fprintln(e.stdout, "calibration is current; nothing to do (use --force to redo it)")
			return nil
		}
		if err := atomicfile.Write(*calibPath, sen.CalibrationData(), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "calibrated %s; saved %s\n", where, *calibPath)
		return nil
	})
}

// openPaired opens the session and checks the sensor against the pin, as
// fpd does on every open (docs/DESIGN.md, finding F1).
func openPaired(e *env, l *validity.Link, secret []byte) (*validity.Session, error) {
	sess, err := validity.Open(l, validity.DeriveHostKeys(secret), e.fwKey)
	if err != nil {
		return nil, err
	}
	adopted, err := trust.CheckPin(e.pinPath, sess.SensorKey())
	if err != nil {
		return nil, err
	}
	if adopted {
		fmt.Fprintf(e.stderr, "pinned this sensor on first use (%s)\n", e.pinPath)
	}
	return sess, nil
}

// ledgerDo applies a change to the enrollment ledger, when fpctl drives the
// sensor itself with fpd stopped. A missing ledger is left for fpd to adopt
// on its next start rather than created half-filled here.
func ledgerDo(e *env, change func(*trust.Ledger) error) error {
	l, exists, err := trust.LoadLedger(e.ledgerPath)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return change(l)
}

// openSession opens the paired sensor's session with the secret at path
// and runs fn over it.
func openSession(e *env, args sessionArgs, fn func(sess *validity.Session, where string) error) error {
	secret, err := hostid.Load(args.secret)
	if err != nil {
		return err
	}
	log := newLogger(e.stderr, args.trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		sess, err := openPaired(e, l, secret)
		if err != nil {
			return err
		}
		return fn(sess, where)
	})
}

type sessionArgs struct {
	secret string
	trace  bool
}

func (a *sessionArgs) register(fs *flag.FlagSet) {
	fs.StringVar(&a.secret, "secret", hostid.DefaultPath, "")
	fs.BoolVar(&a.trace, "trace", false, "")
}

// lookupUser resolves a user name or numeric uid.
func lookupUser(name string) (uint32, string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		if u, err = user.LookupId(name); err != nil {
			return 0, "", fmt.Errorf("no such user %q", name)
		}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, "", err
	}
	return uint32(uid), u.Username, nil
}

// describeUID names a uid.
func describeUID(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return fmt.Sprintf("%s (uid %d)", u.Username, uid)
	}
	return fmt.Sprintf("uid %d", uid)
}

// viaFPD runs a request through fpd. handled is false when fpd is not
// running, and the caller then uses the sensor directly.
func viaFPD(e *env, typ uint16, payload []byte, ev client.Events) (handled bool, err error) {
	err = client.Do(e.socket, typ, payload, ev)
	if errors.Is(err, client.ErrNoDaemon) {
		return false, nil
	}
	return true, err
}

// describeSID names the user a SID stands for where it can.
func describeSID(sid validity.SID) string {
	uid, ok := sid.UID()
	if !ok {
		return sid.String()
	}
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return fmt.Sprintf("%s (uid %d)", u.Username, uid)
	}
	return fmt.Sprintf("uid %d", uid)
}

// openSensor opens the session, then the sensor itself, calibrating it if
// the saved calibration is missing or stale and saving the result.
func openSensor(e *env, sa sessionArgs, calibPath string, fn func(sen *validity.Sensor, sess *validity.Session) error) error {
	saved, err := os.ReadFile(calibPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return openSession(e, sa, func(sess *validity.Session, _ string) error {
		sen, err := validity.OpenSensor(sess, saved)
		if err != nil {
			return err
		}
		did, err := sen.Calibrate(context.Background(), false)
		if err != nil {
			return err
		}
		if did {
			fmt.Fprintln(e.stderr, "calibrated the sensor")
			if err := atomicfile.Write(calibPath, sen.CalibrationData(), 0o600); err != nil {
				return err
			}
		}
		return fn(sen, sess)
	})
}

// interruptible returns a context cancelled on SIGINT, so an abandoned
// scan stops the sensor cleanly.
func interruptible() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

const enrollUsage = `usage: fpctl enroll --user NAME --finger FINGER [--calib PATH] [--secret PATH] [--trace]

Enrolls FINGER (an fprintd name such as right-index-finger) for the user.
Touch the sensor when it lights up and lift between touches; the sensor
decides how many touches it needs. A rejected touch is reported and simply
repeated. Ctrl-C abandons the enrollment.

  --user NAME       user name or uid
  --finger FINGER   which finger
  --calib PATH      calibration data (default ` + defaultCalibPath + `)
  --secret PATH     host secret (default ` + hostid.DefaultPath + `)
  --trace           log every command and reply in hex to stderr
`

func runEnroll(e *env, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fs.String("user", "", "")
	finger := fs.String("finger", "", "")
	calibPath := fs.String("calib", defaultCalibPath, "")
	var sa sessionArgs
	sa.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" || *finger == "" {
		return &usageError{"--user and --finger are required"}
	}
	subtype, ok := validity.FingerSubtype(*finger)
	if !ok {
		return &usageError{fmt.Sprintf("unknown finger %q", *finger)}
	}
	uid, username, err := lookupUser(*name)
	if err != nil {
		return err
	}
	ctx, stop := interruptible()
	defer stop()
	fmt.Fprintf(e.stdout, "enrolling %s for %s: touch the sensor\n", *finger, username)
	handled, err := viaFPD(e, proto.ReqEnroll, proto.U16(proto.U32s(uid), subtype), client.Events{
		Progress: func(n uint32) { fmt.Fprintf(e.stdout, "  touch %d accepted; lift and touch again\n", n) },
		Retry:    func(uint32) { fmt.Fprintln(e.stdout, "  touch not accepted; try again") },
	})
	if handled {
		if err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "enrolled %s for %s\n", *finger, username)
		return nil
	}
	return openSensor(e, sa, *calibPath, func(sen *validity.Sensor, sess *validity.Session) error {
		db := validity.NewDB(sess)
		if stg, err := db.Storage(); err == nil {
			if u, err := db.LookupUser(stg.ID, validity.UIDSID(uid)); err != nil {
				return err
			} else if u != nil {
				for _, f := range u.Fingers {
					if f.Subtype == subtype {
						return fmt.Errorf("%s already has %s enrolled; delete it first", username, *finger)
					}
				}
			}
		} else if !errors.Is(err, validity.ErrNoStorage) {
			return err
		}
		fid, tid, err := sen.Enroll(ctx, validity.UIDSID(uid), subtype, func(ev validity.EnrollEvent) {
			if ev.Err != nil {
				fmt.Fprintf(e.stdout, "  touch not accepted (%v); try again\n", ev.Err)
				return
			}
			fmt.Fprintf(e.stdout, "  touch %d accepted; lift and touch again\n", ev.Touch)
		})
		if err != nil {
			return err
		}
		if err := ledgerDo(e, func(l *trust.Ledger) error {
			return l.Add(trust.Entry{UID: uid, Subtype: subtype, Record: fid, TID: tid})
		}); err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "enrolled %s for %s\n", *finger, username)
		return nil
	})
}

const identifyUsage = `usage: fpctl identify [--calib PATH] [--secret PATH] [--trace]

Waits for a finger on the sensor and reports which enrolled user and finger
it matched. Ctrl-C stops waiting.

  --calib PATH    calibration data (default ` + defaultCalibPath + `)
  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runIdentify(e *env, args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	calibPath := fs.String("calib", defaultCalibPath, "")
	var sa sessionArgs
	sa.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	ctx, stop := interruptible()
	defer stop()
	fmt.Fprintln(e.stdout, "touch the sensor")
	var match *[2]uint32
	handled, err := viaFPD(e, proto.ReqIdentify, proto.U32s(0), client.Events{
		Retry:  func(uint32) { fmt.Fprintln(e.stdout, "  scan not usable; try again") },
		Finger: func(uid uint32, sub uint16) { match = &[2]uint32{uid, uint32(sub)} },
	})
	if handled {
		var re *client.ResultError
		if errors.As(err, &re) && re.Code == proto.ResultNoMatch {
			return errors.New("no match: that finger is not enrolled")
		}
		if err != nil {
			return err
		}
		if match == nil {
			return errors.New("fpd reported a match without saying whose")
		}
		fmt.Fprintf(e.stdout, "match: %s, %s\n", describeUID(match[0]), validity.FingerName(uint16(match[1])))
		return nil
	}
	return openSensor(e, sa, *calibPath, func(sen *validity.Sensor, sess *validity.Session) error {
		m, err := sen.Identify(ctx, func(err error) {
			fmt.Fprintf(e.stdout, "  scan not usable (%v); try again\n", err)
		})
		if errors.Is(err, validity.ErrNoMatch) {
			// One line, and a non-zero exit so scripts can tell.
			return errors.New("no match: that finger is not enrolled")
		}
		if err != nil {
			return err
		}
		db := validity.NewDB(sess)
		who := fmt.Sprintf("user record %d", m.User)
		if u, err := db.User(m.User); err == nil {
			who = describeSID(u.SID)
		}
		fmt.Fprintf(e.stdout, "match: %s, %s\n", who, validity.FingerName(m.Subtype))
		return nil
	})
}

const listUsage = `usage: fpctl list [--secret PATH] [--trace]

Lists the users and fingers enrolled in the sensor's database, with the
database's size and usage. Changes nothing.

  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runList(e *env, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	var sa sessionArgs
	sa.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	who := uint32(proto.AllUsers)
	if os.Geteuid() != 0 {
		who = uint32(os.Getuid())
	}
	byUser := map[uint32][]uint16{}
	var order []uint32
	handled, err := viaFPD(e, proto.ReqList, proto.U32s(who), client.Events{Finger: func(uid uint32, sub uint16) {
		if _, seen := byUser[uid]; !seen {
			order = append(order, uid)
		}
		byUser[uid] = append(byUser[uid], sub)
	}})
	if handled {
		if err != nil {
			return err
		}
		if len(order) == 0 {
			fmt.Fprintln(e.stdout, "no users enrolled")
		}
		for _, uid := range order {
			fmt.Fprintf(e.stdout, "user  %s\n", describeUID(uid))
			for _, sub := range byUser[uid] {
				fmt.Fprintf(e.stdout, "  %s\n", validity.FingerName(sub))
			}
		}
		return nil
	}
	return openSession(e, sa, func(sess *validity.Session, _ string) error {
		db := validity.NewDB(sess)
		info, err := db.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "database  %d bytes, %d used, %d free, %d records\n",
			info.Total, info.Used, info.Free, info.Records)
		stg, err := db.Storage()
		if errors.Is(err, validity.ErrNoStorage) {
			fmt.Fprintln(e.stdout, "no users enrolled (the user storage does not exist yet)")
			return nil
		}
		if err != nil {
			return err
		}
		users, err := db.Users(stg)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Fprintln(e.stdout, "no users enrolled")
		}
		for _, u := range users {
			fmt.Fprintf(e.stdout, "user  %s, record %d\n", describeSID(u.SID), u.ID)
			for _, f := range u.Fingers {
				fmt.Fprintf(e.stdout, "  %-20s record %d\n", validity.FingerName(f.Subtype), f.ID)
			}
		}
		return nil
	})
}

const deleteUsage = `usage: fpctl delete --user NAME [--finger FINGER] [--secret PATH] [--trace]

Deletes one enrolled finger of a user, or with no --finger the user's
record and every finger under it. FINGER is an fprintd name such as
right-index-finger.

  --user NAME       user name or uid
  --finger FINGER   the finger to delete
  --secret PATH     host secret (default ` + hostid.DefaultPath + `)
  --trace           log every command and reply in hex to stderr
`

func runDelete(e *env, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	name := fs.String("user", "", "")
	finger := fs.String("finger", "", "")
	var sa sessionArgs
	sa.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return &usageError{"--user is required"}
	}
	var subtype uint16
	if *finger != "" {
		var ok bool
		if subtype, ok = validity.FingerSubtype(*finger); !ok {
			return &usageError{fmt.Sprintf("unknown finger %q", *finger)}
		}
	}
	uid, username, err := lookupUser(*name)
	if err != nil {
		return err
	}
	if handled, err := viaFPD(e, proto.ReqDelete, proto.U16(proto.U32s(uid), subtype), client.Events{}); handled {
		if err != nil {
			return fmt.Errorf("delete for %s: %w", username, err)
		}
		what := *finger
		if what == "" {
			what = "enrolled fingers"
		}
		fmt.Fprintf(e.stdout, "deleted %s's %s\n", username, what)
		return nil
	}
	return openSession(e, sa, func(sess *validity.Session, _ string) error {
		db := validity.NewDB(sess)
		stg, err := db.Storage()
		if errors.Is(err, validity.ErrNoStorage) {
			return fmt.Errorf("%s has nothing enrolled", username)
		}
		if err != nil {
			return err
		}
		u, err := db.LookupUser(stg.ID, validity.UIDSID(uid))
		if err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("%s has nothing enrolled", username)
		}
		if *finger == "" {
			if err := db.DeleteRecord(u.ID); err != nil {
				return err
			}
			if err := ledgerDo(e, func(l *trust.Ledger) error { return l.Remove(uid, 0) }); err != nil {
				return err
			}
			fmt.Fprintf(e.stdout, "deleted %s and %d enrolled finger(s)\n", username, len(u.Fingers))
			return nil
		}
		for _, f := range u.Fingers {
			if f.Subtype == subtype {
				if err := db.DeleteRecord(f.ID); err != nil {
					return err
				}
				if err := ledgerDo(e, func(l *trust.Ledger) error { return l.Remove(uid, subtype) }); err != nil {
					return err
				}
				fmt.Fprintf(e.stdout, "deleted %s's %s\n", username, *finger)
				return nil
			}
		}
		return fmt.Errorf("%s has no %s enrolled", username, *finger)
	})
}

const statusUsage = `usage: fpctl status [--secret PATH] [--trace]

Opens the paired sensor as fpd does: sends the start-up programs, reads
the pairing back from the TLS partition, and runs the handshake. Prints the
flash layout, firmware state and ROM version read over the session.

  --secret PATH   host secret (default ` + hostid.DefaultPath + `)
  --trace         log every command and reply in hex to stderr
`

func runStatus(e *env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	secretPath := fs.String("secret", hostid.DefaultPath, "")
	trace := fs.Bool("trace", false, "")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	secret, err := hostid.Load(*secretPath)
	if err != nil {
		return err
	}
	log := newLogger(e.stderr, *trace)
	return withSensor(e, log, func(l *validity.Link, where string) error {
		sess, err := openPaired(e, l, secret)
		if err != nil {
			return err
		}
		var r validity.Report
		if r.Flash, err = validity.GetFlashInfo(sess); err != nil {
			return err
		}
		if r.Rom, err = validity.GetRomInfo(sess); err != nil {
			return err
		}
		if r.Fwext, r.FwextStatus, err = validity.GetFirmwareInfo(sess, validity.PartitionFwext); err != nil {
			return err
		}
		fmt.Fprintln(e.stdout, "session  open")
		writeReport(e.stdout, where, r)
		return nil
	})
}

func openSystemSensor() (sensor, string, error) {
	info, err := usbfs.System.Find(validity.VendorID, validity.ProductID)
	if err != nil {
		return nil, "", err
	}
	dev, err := usbfs.Open(usbfs.System, info, 0)
	if errors.Is(err, syscall.EBUSY) {
		return nil, "", fmt.Errorf("the sensor is in use, probably by fpd; stop it first (systemctl stop fpd): %w", err)
	}
	if err != nil {
		return nil, "", err
	}
	where := fmt.Sprintf("%04x:%04x at %s (bus %d, address %d)",
		info.Vendor, info.Product, info.SysPath, info.Bus, info.Addr)
	return dev, where, nil
}

func writeReport(w io.Writer, where string, r validity.Report) {
	fmt.Fprintf(w, "sensor   %s\n", where)
	// The ROM timestamp is printed raw and as a date: it decodes to a
	// plausible build date as unix seconds, but nothing confirms that.
	fmt.Fprintf(w, "rom      %d.%d build %d, product 0x%02x, timestamp 0x%08x (%s), u1 0x%02x\n",
		r.Rom.Major, r.Rom.Minor, r.Rom.Build, r.Rom.Product, r.Rom.Timestamp,
		unixDate(r.Rom.Timestamp), r.Rom.Unknown1)

	f := r.Flash
	if f.Uninitialised {
		fmt.Fprintln(w, "flash    not formatted (no partition table)")
	} else {
		fmt.Fprintf(w, "flash    jedec %04x:%04x, %d blocks x %d bytes, unknown %04x %04x, %d partitions\n",
			f.JedecID0, f.JedecID1, f.Blocks, f.BlockSize, f.Unknown0, f.Unknown1, len(f.Partitions))
		for _, p := range f.Partitions {
			fmt.Fprintf(w, "  partition 0x%02x  type 0x%02x  access 0x%04x  offset 0x%08x  size 0x%08x\n",
				p.ID, p.Type, p.AccessLvl, p.Offset, p.Size)
		}
	}

	if r.Cmd19 != nil {
		fmt.Fprintf(w, "cmd 0x19 %s\n", hexOrEmpty(r.Cmd19))
	}

	if r.Fwext == nil {
		fmt.Fprintf(w, "fwext    not loaded (%s)\n", r.FwextStatus)
		return
	}
	fmt.Fprintf(w, "fwext    %d.%d built %s, %d modules\n",
		r.Fwext.Major, r.Fwext.Minor, unixDate(r.Fwext.BuildTime), len(r.Fwext.Modules))
	for _, m := range r.Fwext.Modules {
		fmt.Fprintf(w, "  module type 0x%04x  subtype 0x%04x  version %d.%d  size %d\n",
			m.Type, m.Subtype, m.Major, m.Minor, m.Size)
	}
}

func unixDate(t uint32) string {
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%16 == 0 {
			sb.WriteString("\n         ")
		} else if i > 0 && i%2 == 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	return sb.String()
}
