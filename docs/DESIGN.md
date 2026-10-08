# t480-fingerprint design

Status: **design, no code yet** (2026-10-07). This file records the decisions
made before the first line was written, so the implementation starts from
them rather than rediscovering them.

## Why this exists

The ThinkPad T480's fingerprint reader is a Synaptics "Metallica" sensor,
USB `06cb:009a`. Mainline libfprint does not support it. The only working
Linux stack is three third-party projects by one author:

| Project | Role | State when evaluated (2026-10-07) |
|---|---|---|
| [python-validity](https://github.com/uunicorn/python-validity) (MIT) | the sensor driver: USB, the sensor's TLS session, pairing, firmware upload, enroll/identify | release 0.15 (2025-06), 181 open issues, maintainer unresponsive; `06cb:009a` does not initialise on Python 3.14 + libusb 1.0.30 without an unmerged patch (#272); resume after S3 fails about half the time (#281) |
| [open-fprintd](https://github.com/uunicorn/open-fprintd) (GPL-2.0) | replaces fprintd's daemon, speaking its D-Bus API | about 420 lines of Python, last release 0.7 (2025-06) |
| fprintd-clients (GPL-2.0+) | `pam_fprintd.so` and the enroll tools without fprintd's daemon | fprintd 1.90.1 (2020-02) plus two 2020 commits, frozen |

Third-party Python in the authentication path, carried with local patches
against an unmaintained upstream, is not acceptable here. So the three are
replaced by one small program of our own, in Go and C. python-validity is
the protocol reference (it is the reverse-engineering); its MIT copyright
notice is kept for the ported parts.

## Shape

```
fpd         Go, root daemon. Owns 06cb:009a through usbdevfs ioctls (no
            libusb, no cgo), runs the sensor's TLS-like session, pairing,
            firmware upload, enroll, identify, delete. Serves a unix socket
            with a small request protocol, checking the peer's credentials
            (SO_PEERCRED).
pam_fpd.so  C11, small. Connects to fpd's socket, asks it to verify the uid
            PAM is authenticating, maps the answer to PAM_SUCCESS /
            PAM_AUTH_ERR / PAM_AUTHINFO_UNAVAIL. No crypto, no USB, no
            parsing beyond a fixed-size reply.
fpctl       Go CLI: enroll, list, delete, pair, fetch-firmware, factory-reset,
            status.
```

The PAM module is C only because PAM loads shared objects; everything that
parses device data or does cryptography is in Go.

## Facts from the reference (python-validity at a6bbc21, "Release 0.15")

- About 5,900 lines, of which about 1,000 are the other three sensors' blobs
  (`blobs_90/97/9d.py`), dropped here. The core to port: `sensor.py` (928
  lines, the command set and the sensor's database), `tls.py` (542, the
  session), `db.py`, `flash.py`, `init_flash.py` (pairing and the flash
  layout), `timeslot.py`, `upload_fwext.py`, `usb.py`, and about 1,600 lines
  of tables and blobs that are data rather than logic.
- Crypto used: ECDH and ECDSA on P-256, AES-CBC, SHA-256, HMAC. All in Go's
  standard library.
- **Matching happens on the sensor.** Prints are enrolled into the sensor's
  flash; the host keeps a user-to-record mapping. No matcher to write, and no
  fingerprint image reaches the host.
- Sensor firmware is Lenovo's, extracted from its Windows driver package
  (`6_07f_lenovo_mis_qm.xpfwext`). The reference downloads the package,
  checks a pinned SHA-512 and extracts the one file with `innoextract`. It is
  proprietary: fetched on the machine, never packaged or published.

## v1 scope

- Pair (first-time sensor setup and the TLS pairing), firmware upload,
  enroll, identify, delete, list, status.
- Factory reset as an `fpctl` command, the recovery path.
- Built in from the start, not patched on later:
  - the #272 initialisation fixes: retry the sensor's transient `0x0104`
    busy status; handle a 2-byte reply from uninitialised flash; upload the
    firmware before any protected-flash command;
  - #281: after resume the USB device re-enumerates, so reopen it rather
    than holding a stale handle.
- PAM wiring on the T480: `sudo` and the Plasma lock screen
  (`/etc/pam.d/kde-fingerprint`, whose `pam_fprintd.so` line becomes
  `pam_fpd.so`), with the password still accepted. Not the SDDM login: that
  login unlocks KWallet, which a fingerprint cannot.

## Phase 2: System Settings enrollment

Plasma's lock screen uses PAM only (`kscreenlocker_greet` has no fprintd
references). Only System Settings' Users page (`kcm_users`) talks to fprintd,
over the system bus, so enrolling from System Settings needs fpd to serve
that API:

- `net.reactivated.Fprint.Manager`: `GetDevices`, `GetDefaultDevice`
- `net.reactivated.Fprint.Device`: `Claim`, `Release`, `EnrollStart`,
  `EnrollStop`, `ListEnrolledFingers`, `DeleteEnrolledFinger`,
  `DeleteEnrolledFingers2`, `VerifyStart`; signal `EnrollStatus`;
  properties `num-enroll-stages`, `scan-type`, `finger-present`,
  `finger-needed`
- a `system.d` bus policy owning `net.reactivated.Fprint`

Using `github.com/godbus/dbus/v5` (approved 2026-10-07; pure Go, BSD-2),
estimated 400-600 lines. Authorization without polkit: a caller may enroll or
delete only their own fingers (the UID the bus reports for the connection);
operations on other users stay root-only through `fpctl`.

## Project conventions

Per the owner's standards: Go modules with the version pinned in `go.mod`,
stdlib first (godbus is the one approved dependency, phase 2), `gofmt`,
`go vet`, golangci-lint with staticcheck, `go test -race`, table-driven tests,
at least 80% line coverage. The C module builds with the strict warning set,
`-fanalyzer`, cppcheck and clang-tidy, tested with cmocka. Makefile build,
artifacts under `build/`. `release_version` drives the version string.

Packaging: an ebuild in vifair-overlay, built and published by the binhost
through the t480 declaration (gitlab-infra).
