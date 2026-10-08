// Command fpctl administers the T480 fingerprint sensor.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"git.airies.net/vifair22/t480-fingerprint/internal/usbfs"
	"git.airies.net/vifair22/t480-fingerprint/internal/validity"
	"git.airies.net/vifair22/t480-fingerprint/internal/version"
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
	e := &env{stdout: os.Stdout, stderr: os.Stderr, open: openSystemSensor}
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
	level := slog.LevelInfo
	if *trace {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(e.stderr, &slog.HandlerOptions{Level: level}))

	dev, where, err := e.open()
	if err != nil {
		return err
	}
	r, perr := validity.Probe(validity.NewLink(dev, log))
	if cerr := dev.Close(); cerr != nil {
		log.Warn("closing sensor", "err", cerr)
	}
	if perr != nil {
		return perr
	}
	writeReport(e.stdout, where, r)
	return nil
}

func openSystemSensor() (sensor, string, error) {
	info, err := usbfs.System.Find(validity.VendorID, validity.ProductID)
	if err != nil {
		return nil, "", err
	}
	dev, err := usbfs.Open(usbfs.System, info, 0)
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

	fmt.Fprintf(w, "cmd 0x19 %s\n", hexOrEmpty(r.Cmd19))

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
