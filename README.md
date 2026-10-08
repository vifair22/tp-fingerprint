# t480-fingerprint

Fingerprint authentication for the ThinkPad T480's Synaptics `06cb:009a`
("Metallica") reader: a Go daemon that drives the sensor, a small C PAM
module, and a CLI. It replaces the python-validity / open-fprintd /
fprintd-clients stack with one program of our own.

Status: working end to end against the real sensor (pairing, firmware,
calibration, enroll, identify, fpd, pam_fpd.so); not yet installed as a
service or wired into /etc/pam.d. See [docs/DESIGN.md](docs/DESIGN.md) for
the decisions, the scope of v1, and the facts taken from the reference
implementation.

## Building

Needs Go (the version in `go.mod`), make, gcc, libpam headers and cmocka;
clang-tidy, cppcheck and gcovr for `make lint` and `make cover`.

```sh
make            # fpd and fpctl into build/bin/, pam_fpd.so into build/lib/
make test       # go test -race, and the C tests under ASan and UBSan
make cover      # Go and C coverage, each failing under 80%
make lint       # gofmt, go vet, golangci-lint when installed, cppcheck,
                # gcc -fanalyzer, the stack-usage check and clang-tidy
make debug race # debug and race-detector builds of the Go programs
make pamcheck   # build/bin/pamcheck, to try the module without /etc/pam.d
```

## Running

`fpctl probe` reads the sensor's flash layout, ROM version and firmware
state and changes nothing, so it is safe on a sensor of unknown history.
It needs read-write access to the device node under `/dev/bus/usb` (root,
or membership of the group that owns it); `--trace` logs every exchange in
hex.

## License

GPL-3.0 (see [LICENSE](LICENSE)). The sensor protocol is ported from
[python-validity](https://github.com/uunicorn/python-validity), which is
MIT-licensed; its copyright notice is kept with the ported code.
