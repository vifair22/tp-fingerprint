# tp-fingerprint design

Status: **installed locally; fingerprint unlocks the lock screen and
1Password, and enrolls from System Settings**
(2026-10-07). fpd runs as a sandboxed systemd service; pam_fpd.so is wired
into `kde-fingerprint` and `sudo`. Everything has run against the real
sensor except factory reset (fakes only) and the three-wrong-tries ending
(tests only). Fingerprint unlocks the lock screen (across suspend) and
1Password through polkit. Hardware tampering evaluated and its
fixes in (see "Threat model"). Phase 2 (System Settings) works. The local
install is the deployment (see "Packaging"). This file records the
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

## The sensor's database (2026-10-07)

Ported from `db.py` and `sid.py`: storage, user and finger records,
lookup by identity, record values and children, create (inside a flash
transaction) and delete. Users are keyed by the reference's uid mapping,
`S-1-5-21-111111111-1111111111-1111111111-<uid>`, padded to the 0x4c-byte
Windows identity union. Deleting a user record deletes its fingers; a
single finger is deleted by its own record, which the reference never
does but the System Settings phase needs.

Unlike the reference, which creates the `StgWindsor` storage at every
start, the storage is created on first enrollment, so `fpctl list` writes
nothing. On the real sensor (still empty) `45` reported 524,288 bytes,
partition 4's size, with 512 used and no records, and the storage lookup
answered `0x04b3` (not found).

## Capture, enroll and identify (2026-10-07)

Ported from `sensor.py`: the capture sequence (command `02` built for the
mode, interrupts for start, finger down and capture updates until bit 4,
the result from `51 00 20 00 00`, always `04` after), enrollment (`69`,
then per touch `68`, `6b`, `6b` until the sensor returns a template id,
then the user and finger records) and identification (`5e` against any
user, `60` for the result, `62` after). Two departures: a run of ten
rejected touches abandons an enrollment, where the reference retries
forever, and only rejected scans and sensor statuses are retried, where the
reference retries any exception but a USB error.

The first real enrollment (right index finger) took 11 touches, none
rejected, and left three records in the database (storage, user, finger)
using 24,320 bytes. `fpctl identify` then matched that finger to the user,
and for other fingers the sensor answered `5e` with interrupt
`04000100db` rather than type `03`, which is reported as no match.

## fpd and pam_fpd.so (2026-10-07)

Decisions, made before writing them:

- fpd keeps one session to the sensor open for its lifetime (the reference
  notes the sensor runs out of memory if new TLS sessions keep coming), and
  checks before every request that the sensor is still at the bus address
  it opened; after a resume it is not (#281), and fpd reopens. Any failure
  below the protocol drops the session for the next request to reopen. On
  shutdown it reboots the sensor, as the reference does on exit.
- Socket `/run/fpd/fpd.sock`, mode 0666; callers are identified by
  `SO_PEERCRED`. Root may act for anyone, others only for themselves;
  identify (which says whose a finger is) is root only.
- Frames are u16 type, u16 length, payload (`internal/proto`,
  `pam/include/fpd_proto.h`, kept equal by a Go test). The PAM module uses
  only VERIFY and the fixed-size PROMPT, RETRY and RESULT events.
- One request at a time. A second gets BUSY at once and the PAM module
  returns `PAM_AUTHINFO_UNAVAIL`, falling back to the password, which is
  what fprintd's single claim and pam_fprintd do.
- Touch operations from a remote login session are refused (RESULT
  REMOTE). The check reads `/proc/<pid>/cgroup` for a `session-N.scope`
  and that session's `REMOTE=` in `/run/systemd/sessions/N`; a process
  outside any session scope (a terminal under the user's systemd
  instance) is local. Anything unreadable counts as local: misjudging a
  remote caller costs it only the timeout.
- Defaults: 15 s timeout (pam_fprintd uses 30), 3 tries.
- Only MATCH grants (`PAM_SUCCESS`) and only NO_MATCH denies
  (`PAM_AUTH_ERR`); everything else is `PAM_AUTHINFO_UNAVAIL`.
- fpctl's list, enroll, delete and identify go through fpd when it runs;
  pair, firmware, calibrate and factory reset need the sensor directly and
  tell the user to stop fpd when it holds the interface.

clang-tidy's analyser found a real defect in the first version of the C
client: unknown frame types were given a sentinel "expected length" of
0xffff, so an unknown frame claiming exactly that length would have been
read into a 4-byte buffer inside sudo. Unknown types are now rejected
before their length is looked at, with a test for that frame.

First run against the real sensor, fpd started by hand: it opened and
warmed the sensor in about a second; `fpctl list` worked as a normal user
through fpd; `fpctl status` explained that fpd held the sensor. Through
`pamcheck` (a driver using `pam_start_confdir` with a scratch service
file), the enrolled finger authenticated, a different finger was rejected
and retried, and no finger timed out to `PAM_AUTHINFO_UNAVAIL`.

## Local installation (2026-10-07)

Until the ebuild exists, `make install` (copy only, so `sudo make
install` never leaves root-owned files in build/) puts `fpd` in
/usr/local/sbin, `fpctl` in /usr/local/bin, `pam_fpd.so` in
/usr/local/lib64/security (outside the package-managed
/usr/lib64/security; PAM loads it by absolute path) and
`packaging/fpd.service` in /etc/systemd/system.

The unit runs fpd with no capabilities, `DevicePolicy=closed` plus
`DeviceAllow=char-usb_device rw`, `ProtectSystem=strict`, AF_UNIX only, a
system-call filter and `UMask=0077`; `systemd-analyze security` rates it
1.5 ("OK"). It needs none of the capabilities it lacks: everything it
opens is root-owned.

PAM, with the originals kept as `*.pre-fpd`:

- `/etc/pam.d/kde-fingerprint`: `-auth required pam_fprintd.so` became
  `-auth required /usr/local/lib64/security/pam_fpd.so`. The leading `-`
  makes a missing module a silent skip. Unlocking with the enrolled finger
  worked first time (matched in about 2.6 s).
- `/etc/pam.d/sudo`: `auth sufficient .../pam_fpd.so` ahead of the
  `system-auth` substack. This user's sudo is `NOPASSWD: ALL`, so the line
  is inert until that changes (kept, by choice). The file is generated by
  the pam eclass, so a sudo update brings a `._cfg` version without the
  line; keep the local one when dispatch-conf asks.

Known: stopping fpd reboots the sensor, which then re-enumerates for a
second or two, so a restart's warm-up can miss it ("sensor not ready");
the first request reopens it.

## The lock screen, suspend and USB power (2026-10-07)

The Plasma lock screen runs its fingerprint stack once per lock and never
restarts it, so after pam_fpd's 15 s timeout fingerprint unlock was gone
until the next lock (seen on the real machine). The `kde-fingerprint` line
now has `timeout=0`: the module sends `FPD_TIMEOUT_NONE` and fpd waits
until a finger arrives or the greeter goes away (unlocking with the
password closes the socket, which cancels the scan). sudo keeps 15 s.

Such a request also has to outlive a suspend, when the sensor drops off
the bus and returns at a new address. A finger request (verify, identify)
whose sensor fails part way, with its caller still waiting, drops the
session, waits for the sensor to return, reopens and scans again, at most
five reopens per request. A request with no deadline that arrives while
the sensor is missing waits for it; one with a deadline is told at once
that the sensor is unavailable.

Holding the device open through usbfs kept it, its root hub and the xHCI
controller awake permanently (1,232 s active, 1 s suspended), costing the
CPU its deeper idle states. fpd now uses `USBDEVFS_ALLOW_SUSPEND` and
`USBDEVFS_FORBID_SUSPEND` (Linux 5.4+): 30 s after a request (`fpd
--idle`) the device may autosuspend. Measured on the real sensor, it loses
its TLS session when suspended (the next encrypted reply is not a TLS
record), so fpd compares the kernel's `power/runtime_suspended_time` from
when it allowed suspend with the value at the next request, and reopens
first if the device actually slept. Back-to-back requests take 0.01 s; the
first after a sleep about 1 s. A lock-screen request waits awake, so the
bus stays up while the machine is locked but not asleep; wake-on-finger
(USB remote wakeup) would fix that and is not explored.

On the real machine (2026-10-07, S3 suspend by closing the lid while
locked): on resume the sensor disconnected (device 10); 49 ms later the
lock screen started its fingerprint request with the sensor absent; the
sensor re-enumerated as device 12; fpd reopened it 1.3 s after the request
arrived; the touch matched 4 s after that. So Plasma starts the lock
screen's fingerprint stack after resume, not before suspend, and it is the
"no deadline waits for a missing sensor" rule that keeps fingerprint
unlock alive across a suspend. The mid-request path (the sensor leaving
while already waiting) is covered by tests only. Also confirmed: waiting
longer than 30 s before touching, unlocking with the password (fpd
cancelled the scan; `fpctl list` answered at once), and 1Password.

1Password (and every polkit prompt) uses `/etc/pam.d/polkit-1`, a local
override of polkit 126's `/usr/lib/pam.d/polkit-1` with `auth sufficient
.../pam_fpd.so` first.

## Threat model: hardware tampering (evaluated 2026-10-08)

Attacker: physical access to the locked or suspended laptop, possibly
opening the case. Goal: pass a fingerprint check (lock screen, polkit and
1Password, sudo if NOPASSWD is ever dropped). Out of scope: an attacker who
is already root, and attacks on the password.

Already holding: the host key is protected by a random root-only secret,
not by the DMI identity (Blackwing's 2023 "A Touch of Pwn" bypass of
Synaptics sensors relied on that derivation); a sensor emulator cannot
finish the handshake without a Synaptics-signed key's private half; matching
is on the sensor and no image reaches the host; firmware is Synaptics-signed
and the uploaded file is pinned; local users act only for themselves and
remote sessions are refused.

What the probes in `internal/validity/hwprobe_test.go` (build tag
`hwprobe`) showed on the real sensor:

- A plaintext command sent while a session is up is refused with status
  `0x0315`, and the sensor drops the session with it. A full re-open
  (which starts in plaintext) therefore fails once, then works.
- A ClientHello sent straight into a live session is answered with an
  alert (record type 0x15), which also ends the session.
- Every new session costs the sensor memory: about 17 in a row without a
  reboot and it disconnected itself mid-command and re-enumerated (a crash
  that amounts to a reset). Suspend resets it too.
- A USB port reset clears a session; a full open works 0.8 s later.
- Match results (`60`): after a match, tagged fields 1 (user record),
  3 (finger), 4 (32 bytes), 2 (varies per match: a score), 5 and 6 (zero).
  Field 4 is the finger's template id (tid), byte for byte the tid in the
  finger record, returned to the host by the sensor at enrollment. After a
  no-match, `60` fails with `0x047a`. Without the `62` cleanup the result
  persists: the next `5e` is refused with `0x04fc`, and `60` still returns
  the previous match.

Findings and what was done for each. F1, F2, F4, F5 and the `0x0315`
retry were implemented on 2026-10-08 and run on the real machine: on the
first start fpd pinned the sensor and adopted the one enrolled finger
(record 5, tid `ca3d6368...`, the value the probes saw in its matches),
and the lock screen then unlocked with the ledger check in force.

- **F1, no sensor pinning (fix).** The host accepts any Synaptics-signed
  sensor key, so a second genuine sensor, paired by the attacker with the
  attacker's finger under the predictable SID and carrying our encrypted
  host-key blob (readable from our sensor in plaintext), might be swapped
  in, provided that sensor can be made to trust our public key (its trust
  anchor is signed with the public `hs_key`; unverified). Done: `fpctl
  pair` pins a SHA-256 of the sensor's ECDH public key in
  `/var/lib/fpd/sensor-pin`; fpd and fpctl check it on every open and
  refuse any other sensor at once (no reopen attempts, which would each
  cost it a session). A pairing made before pinning is pinned on first
  use.
- **F2, the sensor's database is trusted (fix).** Done:
  `/var/lib/fpd/enrolled`, root-only: uid, finger, finger record and tid,
  written on enroll and delete (by fpd, and by fpctl when it drives the
  sensor itself). A verify succeeds only if the match's tid is one
  recorded for that user; identify names the ledger's owner; list shows
  only what the ledger backs; a user missing from it is not enrolled. An
  attacker's template has another tid, and ours is never visible outside
  the session and the ledger. With no ledger file, the sensor's current
  enrollments are adopted once (trust on first use, as root); a new
  pairing starts an empty one.
- **F3, replay within a session (residual).** Record MACs cover type,
  version, length and body with no sequence number (the sensor's protocol),
  so an implant on the internal USB could replay a recorded reply, and
  interrupts are plaintext. A fresh session per verify is not viable: the
  sensor refuses in-place renewal and leaks memory per session; the only
  safe fresh session is reboot plus reopen, 2 to 3 s. Kept as residual
  risk, mitigated by rotation (a new session after every 30 s idle sleep
  and every suspend). An implant in the case could log the keyboard too.
- **F4, stale match results (hardening).** Safe today: `60` fails after a
  no-match once `62` has run, and fpd always runs it and checks `5e`'s
  status. Exploiting the persistence needs F3's replay. Done: `62` is
  sent before `5e` as well as after.
- **F5, unlimited attempts (fix).** Each resume gives the lock screen 3
  fresh tries, so lid cycling gives unbounded attempts with fake prints.
  Done: fpd counts non-matching fingers per user (each touch, not each
  request); the fifth in a row refuses fingerprint for that user for 30
  minutes with RESULT LOCKED_OUT, which pam_fpd shows as "use your
  password". A match resets the count. The state is in memory: only root
  can restart fpd.
- **F6, unauthenticated plaintext commands (accepted).** Factory reset and
  flash reads need no session. A physical attacker can wipe the pairing
  (fingerprint is lost, the password remains) and read the encrypted
  host-key blob (useless without the secret). F1 and F2 close what follows.
- **F7, fake fingers (accepted).** The sensor's matcher and liveness; F5
  limits attempts.
- **F8, the host secret.** Keep an encrypted backup; it is as sensitive as
  the pairing.

Also done: a re-open that meets `0x0315` (the sensor still holding a
session the host dropped) retries at once instead of failing the request.

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
references). Only System Settings' Users page (`kcm_users`, which ships in
plasma-workspace) talks to fprintd, over the system bus, so enrolling from
System Settings needs fpd to serve that API. Read from its 6.7.5 source
(2026-10-08): it calls `GetDefaultDevice` (a failure hides the fingerprint
section), `ListEnrolledFingers(username)` unclaimed (`NoEnrolledPrints`
means none), then `Claim`, `EnrollStart` or `DeleteEnrolledFinger`,
`EnrollStop`, `Release` (`AlreadyInUse` on claim is tolerated), reads the
properties below through `org.freedesktop.DBus.Properties.Get`, and handles
`EnrollStatus` results `enroll-stage-passed`, the retries
(`enroll-retry-scan`, `-swipe-too-short`, `-finger-not-centered`,
`-remove-and-retry`) and the endings (`enroll-completed`, `-failed`,
`-data-full`, `-disconnected`, `-unknown-error`). It does not call
`VerifyStart` or `DeleteEnrolledFingers2`. The interface fpd serves:

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
operations on other users stay root-only, so managing another user's
fingerprints from System Settings is refused unless it runs as root
(accepted 2026-10-08 for this single-user machine).

`num-enroll-stages` is reported as 12 (the sensor decides how many touches
it wants; the first enrollment took 11): stage-passed signals stop after
the eleventh and completion fills the progress circle, so it never
overshoots.

Order of work: the tampering fixes F1, F2, F4, F5 and the `0x0315` re-open
retry first (done 2026-10-08), then the D-Bus service, then a test from
System Settings, then the ebuild.

Done 2026-10-08: `internal/fprint` serves the API above from inside fpd
(`--no-dbus` turns it off; without a bus or with the name taken fpd runs
on without it). It takes the sensor through the socket server's lock, so a
D-Bus enrollment and a lock-screen or sudo request never run together; the
second gets busy. A claim is held per bus connection and released when the
connection leaves the bus. Enrolling an enrolled finger replaces it, as
fprintd does. `packaging/net.reactivated.Fprint.conf` lets root own the
name and anyone call it. Tests run the service on a private `dbus-daemon`.
golang.org/x/sys v0.27.0 came in as godbus's own dependency.

On the real machine, from System Settings (Plasma 6.7.5): the dialog
listed the right index finger, re-enrolling it replaced the template
(record 5 kept, tid `ca3d6368...` became `035655ba...` in the ledger), and
the lock screen then unlocked with the new template.

## Second sensor: the C14's fingerprint MCU (2026-10-14)

The ThinkPad C14 Chromebook has no USB sensor but a ChromeOS fingerprint
MCU ("bloonchipper", an STM32F412 driving an FPC sensor, `FPC ` vendor
`0x20435046`, product 9, model `0x21f`), reached through the kernel's
cros_ec character device `/dev/cros_fp`. fpd drives it with a second
backend behind `server.Reader`, so the socket protocol, pam_fpd.so, fpctl's
client side and the fprintd D-Bus API are unchanged. `--sensor auto` (the
default) picks it when `/dev/cros_fp` exists; the T480 has none and keeps
the validity backend.

| Package | What |
|---|---|
| `internal/crosfp` | the MCU's host commands and events over the chardev: `CROS_EC_DEV_IOCXCMD_V2` and the fingerprint event mask, in Go with no cgo |
| `internal/crosfp/crosfptest` | a simulated MCU for tests |
| `internal/crosdev` | the reader: seed, context, template store, enroll, match |

The MCU is not a sensor the host drives. It captures, enrolls and matches
itself, and keeps up to `template_max` templates (5 here, 5156 bytes each,
format 4). It hands each one out encrypted under a key it derives from a
seed the host sets once per MCU boot and a user context; the host stores
them and uploads them again after every MCU reset.

Read on the C14 with the firmware it shipped (RW `bloonchipper-v2.0.30778`,
2026-04-15): `FP_INFO` answers versions 2 and 3 only, `FP_CONTEXT` version
1 only (asynchronous), `FP_SEED` and `FP_ENC_STATUS` version 0. The GSC
pairing commands (`FP_ESTABLISH_PAIRING_KEY_*`, `FP_GENERATE_NONCE`,
`FP_ESTABLISH_SESSION`) are present, but the older seed and context scheme
is still accepted, and that is what this backend uses.

Decisions:

- **One context for fpd, not one per user.** The MCU holds one user
  context at a time and setting it clears its templates, while fpd serves
  every user. So the context is derived from the host secret
  (`HMAC-SHA256(secret, "fpd crosfp context v1")`) and the owner of each
  template is kept on the host: one file per finger,
  `/var/lib/fpd/crosfp/<uid>-<finger>.tpl`, uploaded in uid then finger
  order, so the MCU's match index names the finger.
- **The seed** is `HMAC-SHA256(secret, "fpd crosfp seed v1")`, set when the
  MCU reports none. A seed already set is trusted to be fpd's (a restarted
  fpd). If someone else set it first, every stored template fails to load:
  reported, never deleted.
- **Enroll** repeats `ENROLL_SESSION | ENROLL_IMAGE` and waits for the
  finger to lift between touches, as ChromeOS's biod does; rejected touches
  (low quality, immobile, low coverage) are passed to progress as errors,
  which the fprintd API shows as retry-scan. The new template is read back
  encrypted with `FP_FRAME` and stored.
- **Match** handles the MCU refining a template (`MATCH_YES_UPDATED`) by
  reading it back and storing it again; failing that is logged, not fatal.
- After each match result fpd waits briefly for the finger to lift, so one
  touch is not counted twice, and between requests it leaves the MCU in no
  mode.

Not covered yet: the GSC pairing scheme (binding the template key to the
Cr50 rather than to the host secret), and the MCU's sensor maintenance
pass (`FP_MODE_SENSOR_MAINTENANCE`, which counts dead pixels; `errors`
reads `0x3ff`, "unknown", until one has run).

### Prompt LED (2026-10-14)

The C14's sensor has no light, so nothing shows when a touch will be read.
`--prompt-led NAME` (`internal/promptled`) flashes a kernel LED class
device from the moment a request prompts until it ends: verify, identify
and enroll, whatever the outcome. On the C14 that is the power LED,
`chromeos:red:power` (the cros_ec LED driver's name; the LED is white), at
100 ms on, 100 ms off.

- **The kernel flashes it, not fpd.** fpd selects the `timer` trigger
  (`ledtrig-timer`, which has to be loaded) and sets the rate; every toggle
  is a host command to the EC, and only while a request waits.
- **The resting trigger is put back**, by default the one active when fpd
  started: `chromeos-auto` on the C14, which hands the LED back to the EC,
  so its normal on/off and its breathing in S0ix carry on. Overlapping
  requests (the lock screen and an enroll) share the flash; it stops with
  the last.
- **A crash cannot leave it flashing for good.** An fpd that finds `timer`
  already active refuses to guess the resting trigger unless
  `--prompt-led-restore` names it, and then puts it back at once. The C14's
  unit names it.
- **Optional.** Without the flag fpd is unchanged, and an LED that cannot
  be opened is a warning, not a failed start. The unit's sandbox makes /sys
  read-only, so a machine that uses it adds a `ReadWritePaths=` for that
  LED's directory in a drop-in (the C14's is in the thinkpad-c14
  repository).

The lock screen keeps a verify running while it is up, so there the LED
flashes the whole time.

## Project conventions

Per the owner's standards: Go modules with the version pinned in `go.mod`,
stdlib first (godbus is the one approved dependency, phase 2), `gofmt`,
`go vet`, golangci-lint with staticcheck, `go test -race`, table-driven tests,
at least 80% line coverage. The C module builds with the strict warning set,
`-fanalyzer`, cppcheck and clang-tidy, tested with cmocka. Makefile build,
artifacts under `build/`. `release_version` drives the version string.

Packaging: none, by decision (2026-10-08). The project serves this one
laptop, so `make install` into /usr/local plus the hand-made PAM and polkit
wiring (see "Local installation") is the deployment, not a stopgap. An
ebuild in vifair-overlay, built by the binhost through the t480
declaration, remains the route if that changes. What that means for upkeep:

- After changing the code: `make`, then `sudo make install` and
  `sudo systemctl restart fpd`. Restarting reboots the sensor; the first
  request after it reopens the session.
- Portage does not know these files. /usr/local and /etc/systemd/system
  are untouched by updates; /etc/pam.d/sudo is regenerated by sudo updates
  (keep the local version), and kde-fingerprint and polkit-1 are left
  alone, the latter being a local override of polkit's vendor file.
- /var/lib/fpd (host secret, sensor pin, ledger, calibration, firmware)
  is state: back it up encrypted; `make uninstall` leaves it in place.
