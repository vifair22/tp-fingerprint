# t480-fingerprint

Fingerprint authentication for the ThinkPad T480's Synaptics `06cb:009a`
("Metallica") reader: a Go daemon that drives the sensor, a small C PAM
module, and a CLI. It replaces the python-validity / open-fprintd /
fprintd-clients stack with one program of our own.

Status: design only. See [docs/DESIGN.md](docs/DESIGN.md) for the decisions,
the scope of v1, and the facts taken from the reference implementation.

## License

GPL-3.0 (see [LICENSE](LICENSE)). The sensor protocol is ported from
[python-validity](https://github.com/uunicorn/python-validity), which is
MIT-licensed; its copyright notice is kept with the ported code.
