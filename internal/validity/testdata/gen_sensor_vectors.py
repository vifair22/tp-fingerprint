#!/usr/bin/env python3
"""Generate sensor_vectors.json by running python-validity's own Sensor code.

Run from a python-validity checkout (a6bbc21, release 0.15):

    cd ~/git/home/python-validity
    python3 <this file> > <tp-fingerprint>/internal/validity/testdata/sensor_vectors.json

pyusb is stubbed out; nothing touches hardware. The inputs (factory values,
raw frames) are pseudo-random from a fixed seed, so the file is
reproducible.
"""
import json
import os
import random
import sys
import types
from hashlib import sha256
from struct import pack

sys.path.insert(0, os.getcwd())

usb = types.ModuleType('usb')
core = types.ModuleType('usb.core')
class USBError(Exception):
    pass
core.USBError = USBError
core.find = lambda **k: None
core.Device = object
usb.core = core
sys.modules['usb'] = usb
sys.modules['usb.core'] = core

from validitysensor import sensor as S
from validitysensor import timeslot as prg
from validitysensor.table_types import SensorTypeInfo, SensorCaptureProg
from validitysensor import generated_tables  # noqa: F401 (fills the tables)

rnd = random.Random(7)

class Obj:
    pass

s = S.Sensor()
s.device_info = Obj(); s.device_info.type = 0x199
s.type_info = SensorTypeInfo.get_by_type(0x199)
s.key_calibration_line = 0x38
s.calibration_frames = 3
s.calibration_iterations = 3
s.rom_info = Obj(); s.rom_info.product = 0x30; s.rom_info.major = 6
s.hardcoded_prog = [b''.join(p.blobs) for p in SensorCaptureProg.table if p.dev_type == 0x199][0]
lines_2d = [int.from_bytes(v, 'little') for k, v in prg.split_chunks(s.hardcoded_prog) if k == 0x2f][0]
s.lines_per_frame = lines_2d * s.type_info.repeat_multiplier
s.bytes_per_line = s.type_info.bytes_per_line
# Spread like real factory values: a narrow band around 0x80.
s.factory_calibration_values = bytes(rnd.randrange(0x70, 0x90) for _ in range(0x90))
s.calib_data = b''

frame_size = s.lines_per_frame * s.bytes_per_line
raw_len = (s.calibration_frames * s.lines_per_frame + 1) * s.bytes_per_line

out = {
    'factory_values': s.factory_calibration_values.hex(),
    'lines_per_frame': s.lines_per_frame,
    'cmd02_uncalibrated': {},
    'passes': [],
}
for mode in ('CALIBRATE', 'IDENTIFY', 'ENROLL'):
    out['cmd02_uncalibrated'][mode] = s.build_cmd_02(S.CaptureMode[mode]).hex()

for i in range(3):
    raw = bytes(rnd.randrange(0x60, 0xa0) for _ in range(raw_len))
    avg = s.average(raw)
    s.process_calibration_results(avg)
    out['passes'].append({'raw': raw.hex(), 'average': avg.hex(), 'calib_after': s.calib_data.hex()})

out['key_line'] = s.get_key_line().hex()
u, m, b = S.bitpack(s.factory_calibration_values)
out['bitpack'] = {'bits': u, 'min': m, 'packed': b.hex()}
out['cmd02_calibrated'] = {}
for mode in ('CALIBRATE', 'IDENTIFY', 'ENROLL'):
    out['cmd02_calibrated'][mode] = s.build_cmd_02(S.CaptureMode[mode]).hex()

# The clean slate framing, as calibrate() writes it.
blank = s.average(bytes(rnd.randrange(0x60, 0xa0) for _ in range(raw_len)))
cs = pack('<H', len(blank)) + blank + pack('<H', 0)
cs = pack('<H', len(cs)) + sha256(cs).digest() + b'\0' * 0x20 + cs
cs = pack('<H', 0x5002) + cs
out['clean_slate'] = {'frame': blank.hex(), 'framed': cs.hex()}

json.dump(out, sys.stdout, indent=1)
