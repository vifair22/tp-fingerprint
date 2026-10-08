# t480-fingerprint design

Status: **sensor paired, firmware loaded, calibrated** (2026-10-07).
Transport, probe, TLS session, pairing, firmware fetch and upload,
calibration and factory reset are written; all but factory reset have run
against the real sensor. Next: the sensor's database (`db.py`), then
capture, enroll and identify. This file records the
decisions made before the first line was written, so the implementation
starts from them rather than rediscovering them, and what the real sensor
has shown since.

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

## This T480's sensor (first probe, 2026-10-07)

The laptop was bought used, so the sensor's history was unknown. `fpctl
probe` sends only the read-only commands the reference sends before it
first writes (`3e`, `01`, `19`, `43 02`) and reported:

- ROM 6.7 build 164, product 0x30; the ROM timestamp 0x545eb0f0 decodes to
  2014-11-09 as unix seconds.
- Flash: JEDEC `c8:40`, 4096 x 256 bytes, which is the GigaDevice GD25Q80C
  (1 MiB) in the reference's IC table. The header is present but the
  partition table is **empty**, so nothing has paired with this sensor (or
  it was factory-reset). Pairing starts from a clean slate: the
  reference's `init_flash` would format it.
- `43 02` (fwext header) answered status **`0x04af`**, not the `0x04b0`
  "no firmware" the reference checks for. The reference's `send_init`
  treats any non-zero status there as a clean slate, so it never tripped on
  it. Read here as "no such partition", which fits the empty table; that
  name is an inference from one observation.
- No `0x0104` busy replies on a cold open. The retry stays in.
- Command `0x19`'s reply is not constant between runs (bytes around offset
  0x1a change), so it probably holds a counter or a nonce. Its meaning is
  still unknown.

## First pairing (2026-10-07)

`fpctl pair` on the unpartitioned sensor, in the #272 order (send_init,
then `reset_blob`, then `4f`), succeeded on the first run with no busy
replies. What it showed:

- The sensor's ECDH key from `50` verifies against the Synaptics key in
  the reference, and the handshake completes with fixed 32-byte
  ClientKeyExchange coordinates.
- The certificate `4f` returns (stored as TLS block 3) is 0xb8 bytes and
  is our own key structure from the host certificate, echoed back.
- After the reboot the device re-enumerated (address 3 to 5), as #281
  describes; finding it fresh on each open covers that.
- `43 02` now answers `0x04b0` (no firmware) where it answered `0x04af`
  before partitioning, which confirms `0x04af` as "no such partition".
- After formatting, the flash header's first unknown field went from
  `0x0010` to `0x0001`, and the ROM info's last byte from 0 to 2. Neither
  is understood.

## First firmware upload (2026-10-07)

`fpctl fetch-firmware` pulled `nz3gf07w.exe` (7,244,088 bytes, matching
the reference's pinned SHA-512) and extracted `6_07f_lenovo_mis_qm.xpfwext`
with innoextract 1.10-dev. The file is pinned too: 218,482 bytes, SHA-256
`ed2b1b5818c4072dd5c1a66e5d556888e81e3806ab0fc653164bea823ccfa2b1`, header
`FirmwareVersion = 6.07.0164` (the ROM is 6.7 build 164). It is a 20,210-byte
text header ending in `0x1a`, a 198,016-byte image, and a 256-byte signature.

`fpctl upload-firmware` then:

- read 3 from register `0x80002080` after writing 7 to `0x8000205c`;
- got major 0x190, minor 0x4a from identify (`75`);
- wrote the image in 49 commands (48 x 0x1000, then 0x580), each
  acknowledged with the length written; the signature was accepted;
- read back firmware 1.2, built 2020-01-27, 8 modules, and rebooted.

After the reboot (re-enumerated again, address 5 to 6) `fpctl status`
opened a session at the first attempt and listed the same firmware. Its
modules are the types and subtypes in the reference's annotated `43 02`
reply, at newer versions.

## Sensor model and calibration (2026-10-07)

Identify (`75`) reports hardware 0x190 version 0x4a: `57K0 FM-3367-001`,
sensor type 0x199, one of the two types the reference has constants for
and a "line update type 1" device. Exactly one capture program in the
reference's generated tables applies (ROM major 6, type 0x199, 648 bytes);
it is the only one carried.

The capture command (`02`) is built by patching that program: the timeslot
table's Call repeats and addresses, the key calibration line spliced in,
the factory value written into the last `0x8000203c` register write, and
the line update tables. The port is held byte for byte to the reference by
`internal/validity/testdata/sensor_vectors.json`, which
`gen_sensor_vectors.py` produces by running python-validity's own `Sensor`
code with pyusb stubbed out.

Calibration data is kept in `/var/lib/fpd/calib-data.bin` (decided
2026-10-07), not in a tmpfs as the reference does. The reference therefore
recalibrates at every boot and, since each blank image differs slightly,
erases and rewrites flash partition 6 every time. Here the sensor is
calibrated once; each later start checks partition 6's hash and skips the
captures when it is valid. `fpctl calibrate --force` redoes it.

First calibration on the real sensor: each of the four captures returned
exactly (3 x 224 + 1) x 120 = 80,760 bytes, the line count the command
asks for. The 13,440-byte calibration data averages +0.52 as signed
corrections (range -37 to +111). A second run found everything current
and captured nothing.

## Pairing identity (decided 2026-10-07)

Pairing has the host generate its own P-256 key, encrypt it under keys
derived from a host identity (`DeriveHostKeys`), and store the blob in the
sensor's TLS partition. The sensor never sees the identity or the derived
keys, so the binding is entirely host-side and the identity is our choice.

The reference uses the DMI product name and serial. Here it is **a random
32-byte secret in a root-only file** (under `/var/lib/fpd`), because:

- the DMI serial now comes from our own coreboot build, and a build that
  reports it differently would orphan the pairing;
- the serial is printed on the laptop's underside, so it is not a secret.

The cost: the file must be backed up. Losing it means a factory reset and
re-enrolling, not data loss. `DMIIdentity` stays in the code, for reading
a sensor paired by the reference.

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
