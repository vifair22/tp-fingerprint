# t480-fingerprint

Fingerprint authentication for the ThinkPad T480's Synaptics `06cb:009a`
("Metallica") reader: a Go daemon that drives the sensor, a small C PAM
module, and a CLI. It replaces the python-validity / open-fprintd /
fprintd-clients stack with one program of our own.

Status: early. The USB transport and `fpctl probe` work against the real
sensor; the TLS session, pairing and everything after it are not written
yet. See [docs/DESIGN.md](docs/DESIGN.md) for the decisions, the scope of
v1, and the facts taken from the reference implementation.

## Building

Needs Go (the version in `go.mod`) and make.

```sh
make            # release build into build/bin/
make test       # go test -race
make cover      # coverage report in build/coverage/, fails under 80%
make lint       # gofmt, go vet, golangci-lint when installed
make debug race # build/bin/fpctl.debug, build/bin/fpctl.race
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
