package validity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// SensorType holds what the reference knows about one sensor type: the
// row of its SensorTypeInfo table plus the constants sensor.py hardcodes
// per type. Only type 0x199, the T480's, is carried.
type SensorType struct {
	Type                    uint16
	BytesPerLine            int
	RepeatMultiplier        int
	LinesPerCalibrationData int
	LineWidth               int
	CalibrationBlob         []byte
	// From Sensor.open: "(lines_per_calibration_data/2), but hardcoded
	// for sensor type 0x199", and two counts the reference also guessed.
	KeyCalibrationLine    int
	CalibrationFrames     int
	CalibrationIterations int
}

var sensorType199 = SensorType{
	Type:                    0x199,
	BytesPerLine:            0x78,
	RepeatMultiplier:        2,
	LinesPerCalibrationData: 112,
	LineWidth:               112,
	CalibrationBlob: mustHex("9b9a999796959392918f8e8d8b8a898786858382817f7e7d7b7a797776757372716f6e6d" +
		"6b6a696766656362615f5e5d5b5a595756555251504e4d4c4a49484645444241403e3d3c3a39383635343231302e2d2c" +
		"2a29282625242221201e1d1c1a19181615141211100e0d0c0a090806"),
	KeyCalibrationLine:    0x38,
	CalibrationFrames:     3,
	CalibrationIterations: 3,
}

// Identify (0x75) versions that hw_tables.py maps to sensor type 0x199,
// all under hardware major 0x190. This T480's sensor reports 0x4a,
// "57K0 FM-3367-001".
var type199Versions = []uint16{74, 87, 89, 90, 91, 96, 97, 98, 104, 105, 106, 118, 126, 130, 137, 142}

const sensorMajor = 0x190

// The one capture program generated_tables.py has for type 0x199: ROM
// major 6, a0 0x18, a1 0x19.
var captureProg199 = loadBlob("capture_prog_199")

// ErrUnsupportedSensor is returned for a sensor model or ROM this port
// carries no tables for.
var ErrUnsupportedSensor = errors.New("unsupported sensor")

// CaptureMode selects how command 0x02 is built.
type CaptureMode int

// Capture modes, as the reference's CaptureMode.
const (
	ModeCalibrate CaptureMode = iota + 1
	ModeIdentify
	ModeEnroll
)

// Sensor is an opened, calibrated sensor: the session plus everything the
// capture command is built from.
type Sensor struct {
	sess *Session
	typ  *SensorType
	rom  RomInfo
	prog []byte
	// lines per frame of the capture program, after the repeat
	// multiplier
	linesPerFrame int
	// factory calibration values (factory bits subtag 3)
	factoryValues []byte
	// host-side calibration accumulated by Calibrate; persisted by the
	// caller between runs
	calib []byte
}

// OpenSensor identifies the sensor, selects its capture program and
// reads its factory calibration, as Sensor.open does up to calibrate().
// calib is the calibration data a previous run saved, or nil.
func OpenSensor(sess *Session, calib []byte) (*Sensor, error) {
	major, minor, err := IdentifySensor(sess)
	if err != nil {
		return nil, err
	}
	typ, err := lookupSensorType(major, minor)
	if err != nil {
		return nil, err
	}
	rom, err := GetRomInfo(sess)
	if err != nil {
		return nil, err
	}
	if rom.Major != 6 {
		return nil, fmt.Errorf("%w: no capture program for ROM %d.%d", ErrUnsupportedSensor, rom.Major, rom.Minor)
	}
	if want := typ.LinesPerCalibrationData * typ.BytesPerLine; calib != nil && len(calib) != want {
		sess.link.log.Warn("ignoring saved calibration of the wrong size", "bytes", len(calib), "want", want)
		calib = nil
	}
	s := &Sensor{sess: sess, typ: typ, rom: rom, prog: captureProg199, calib: calib}
	if s.linesPerFrame, err = linesPerFrame(s.prog, typ); err != nil {
		return nil, err
	}
	bits, err := GetFactoryBits(sess, 0x0e00)
	if err != nil {
		return nil, err
	}
	v, ok := bits[3]
	if !ok || len(v) < 4 {
		return nil, errors.New("factory bits: no calibration values (subtag 3)")
	}
	s.factoryValues = v[4:]
	if len(s.factoryValues) <= typ.KeyCalibrationLine {
		return nil, fmt.Errorf("factory bits: %d calibration values", len(s.factoryValues))
	}
	return s, nil
}

func lookupSensorType(major, minor uint16) (*SensorType, error) {
	if major == sensorMajor {
		for _, v := range type199Versions {
			if v == minor {
				return &sensorType199, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: hardware 0x%x version 0x%x", ErrUnsupportedSensor, major, minor)
}

// linesPerFrame reads the 2D chunk (0x2f) of the capture program.
func linesPerFrame(prog []byte, typ *SensorType) (int, error) {
	cs, err := splitChunks(prog)
	if err != nil {
		return 0, err
	}
	for _, c := range cs {
		if c.typ == 0x2f && len(c.data) >= 4 {
			return int(binary.LittleEndian.Uint32(c.data)) * typ.RepeatMultiplier, nil
		}
	}
	return 0, errors.New("capture program has no 2D chunk")
}

// CalibrationData returns the host-side calibration to persist.
func (s *Sensor) CalibrationData() []byte { return s.calib }

// GetFactoryBits runs command 0x6f for tag and returns the values by
// subtag.
func GetFactoryBits(c Commander, tag uint16) (map[uint16][]byte, error) {
	req := []byte{0x6f}
	req = binary.LittleEndian.AppendUint16(req, tag)
	req = append(req, 0, 0, 0, 0, 0, 0)
	p, err := c.CmdOK(req)
	if err != nil {
		return nil, err
	}
	return parseFactoryBits(p)
}

func parseFactoryBits(p []byte) (map[uint16][]byte, error) {
	if len(p) < 8 {
		return nil, fmt.Errorf("factory bits: %d-byte header: %w", len(p), ErrShortReply)
	}
	count := int(binary.LittleEndian.Uint32(p[4:]))
	p = p[8:]
	out := map[uint16][]byte{}
	for range count {
		if len(p) < 12 {
			return nil, fmt.Errorf("factory bits: %d-byte entry header: %w", len(p), ErrShortReply)
		}
		n := int(binary.LittleEndian.Uint16(p[4:]))
		sub := binary.LittleEndian.Uint16(p[8:])
		p = p[12:]
		if len(p) < n {
			return nil, fmt.Errorf("factory bits: subtag %d: %d of %d bytes: %w", sub, len(p), n, ErrShortReply)
		}
		out[sub] = append([]byte(nil), p[:n]...)
		p = p[n:]
	}
	if len(p) > 0 {
		return nil, fmt.Errorf("factory bits: %d bytes after the last entry", len(p))
	}
	return out, nil
}

// --- building command 0x02 ---

// patchTimeslotTable is the reference's patch_timeslot_table, "the exact
// logic from the DLL": multiply the repeat count of every Call and bump
// its address, scanning only until the first instruction it does not
// recognise. A byte overflow is an error, as it is in the reference.
func patchTimeslotTable(b []byte, incAddress bool, mult int) ([]byte, error) {
	b = append([]byte(nil), b...)
	i := 0
	for i+3 < len(b) {
		switch {
		case b[i]&0xf8 == 0x10:
			if b[i+2] > 1 {
				v := int(b[i+2]) * mult
				if v > 0xff {
					return nil, fmt.Errorf("timeslot table: repeat count overflows at 0x%x", i)
				}
				b[i+2] = byte(v)
				if incAddress {
					if b[i+1] == 0xff {
						return nil, fmt.Errorf("timeslot table: call address overflows at 0x%x", i)
					}
					b[i+1]++
				}
			}
			i += 3
		case b[i] == 0:
			i++
		case b[i] == 7:
			i += 2
		default:
			return b, nil
		}
	}
	return b, nil
}

// patchTimeslotAgain is patch_timeslot_again: follow the last Call before
// the end of the table, and in the routine it calls, set the last write
// to register 0x8000203c from the factory value at the key calibration
// line.
func (s *Sensor) patchTimeslotAgain(b []byte) ([]byte, error) {
	b = append([]byte(nil), b...)
	target := -1
	if err := walkUntilEnd(b, 0, func(pc int, in insn) {
		if in.op == tsCall {
			target = in.args[1]
		}
	}); err != nil {
		return nil, err
	}
	if target < 0 {
		return b, nil
	}
	write := -1
	if err := walkUntilEnd(b, target, func(pc int, in insn) {
		if in.op == tsRegWrite && in.args[0] == 0x8000203c {
			write = pc
		}
	}); err != nil {
		return nil, err
	}
	if write < 0 {
		return b, nil
	}
	b[write+1] = s.factoryValues[s.typ.KeyCalibrationLine]
	return b, nil
}

// walkUntilEnd decodes from pc until End of Table, Return or End of Data.
func walkUntilEnd(b []byte, pc int, visit func(int, insn)) error {
	for pc < len(b) {
		in, err := decodeInsn(b[pc:])
		if err != nil {
			return fmt.Errorf("timeslot table at 0x%x: %w", pc, err)
		}
		if in.op == tsEndOfTable || in.op == tsReturn || in.op == tsEndOfData {
			return nil
		}
		visit(pc, in)
		pc += in.size
	}
	return nil
}

// keyLine is get_key_line: the calibration line the timeslot table
// starts with, with every 5 lowered to 4.
func (s *Sensor) keyLine() []byte {
	if len(s.calib) == 0 {
		return make([]byte, s.typ.LineWidth)
	}
	per := len(s.calib) / s.typ.LinesPerCalibrationData
	off := 8 + per*s.typ.KeyCalibrationLine
	line := append([]byte(nil), s.calib[off:off+s.typ.LineWidth]...)
	for i, c := range line {
		if c == 5 {
			line[i] = 4
		}
	}
	return line
}

// bitpack packs values as (v - min) in the fewest bits that hold the
// largest, least significant first, as the reference's bitpack.
func bitpack(vals []byte) (bits int, minimum byte, packed []byte, err error) {
	minimum, maximum := vals[0], vals[0]
	for _, v := range vals {
		minimum, maximum = min(minimum, v), max(maximum, v)
	}
	for d := maximum - minimum; d > 0; d >>= 1 {
		bits++
	}
	if bits == 0 {
		// The reference fails here too (it slices bin() with [-0:]).
		return 0, 0, nil, errors.New("bitpack: all values equal")
	}
	packed = make([]byte, (bits*len(vals)+7)/8)
	for i, v := range vals {
		d := int(v - minimum)
		for k := range bits {
			if d>>k&1 == 1 {
				bit := i*bits + k
				packed[bit/8] |= 1 << (bit % 8)
			}
		}
	}
	return bits, minimum, packed, nil
}

// Fixed fragments sensor.py appends for identify and enroll (line update
// type 1). Their meaning is not known beyond the names of the chunk types.
var (
	fragIdentify4e = mustHex("fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000")
	fragIdentify2e = mustHex("0200180002000000700070004d010000a0008c003c32321e3c0a0202")
	fragEnroll26   = mustHex("fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000")
	fragEnroll2e   = mustHex("0200180023000000700070004d010000a0008c003c32321e3c0a0202")
)

type updateLine struct {
	mask, flags uint32
	data        []byte
	v0, v1      byte
	v2          uint16
}

func (l updateLine) slot() uint32 { return (l.flags & 0x00f00000) >> 20 }

// lineUpdateType1 is line_update_type_1, the variant for type 0x199.
func (s *Sensor) lineUpdateType1(mode CaptureMode, cs []chunk) ([]chunk, error) {
	var tst []byte
	for i := range cs {
		if cs[i].typ != 0x34 {
			continue
		}
		t, err := patchTimeslotTable(cs[i].data, true, s.typ.RepeatMultiplier)
		if err != nil {
			return nil, err
		}
		if mode != ModeCalibrate {
			if t, err = s.patchTimeslotAgain(t); err != nil {
				return nil, err
			}
		}
		if len(t) < s.typ.LineWidth {
			return nil, errors.New("timeslot table shorter than a line")
		}
		tst = t
		cs[i].data = concat(s.keyLine(), t[s.typ.LineWidth:])
	}
	if tst == nil {
		return nil, errors.New("capture program has no timeslot table")
	}

	cs = append(cs, chunk{0x17, nil})
	switch mode {
	case ModeIdentify:
		cs = append(cs, chunk{0x4e, fragIdentify4e}, chunk{0x2e, fragIdentify2e})
	case ModeEnroll:
		cs = append(cs, chunk{0x26, fragEnroll26}, chunk{0x2e, fragEnroll2e})
	}
	cs = append(cs, chunk{0x44, []byte{1, 0, 0, 0}})

	// The searches run over the patched table without the key line
	// spliced in, as in the reference.
	rx, err := findNthInsn(tst, tsEnableRx, 2)
	if err != nil {
		return nil, fmt.Errorf("second Enable Rx: %w", err)
	}
	reg, err := findNthRegWrite(tst, 0x8000203c, 1)
	if err != nil {
		return nil, fmt.Errorf("write to 0x8000203c: %w", err)
	}
	bits, lo, packed, err := bitpack(s.factoryValues)
	if err != nil {
		return nil, err
	}
	lines := []updateLine{
		{mask: 0xff, flags: uint32(rx+1) | 2<<20 | 0x7000000, data: s.typ.CalibrationBlob, v0: 0xf},
		{mask: 0xff, flags: uint32(reg+1) | 3<<20 | 0x7000000, data: packed, v0: byte(bits-1) | 8, v1: lo},
	}
	if len(s.calib) > 0 {
		per := len(s.calib) / s.typ.LinesPerCalibrationData
		for i := 0; i < 112; i += 4 {
			var d []byte
			for j := range 112 {
				p := 8 + j*per + i
				d = append(d, s.calib[p:p+4]...)
			}
			lines = append(lines, updateLine{mask: 0xffffffff, flags: uint32(i) | 0x85<<24, data: d})
		}
	}
	for i := range lines {
		if pad := len(lines[i].data) % 4; pad > 0 {
			lines[i].data = concat(lines[i].data, make([]byte, 4-pad))
		}
	}

	update := binary.LittleEndian.AppendUint32(nil, uint32(len(lines)))
	for _, l := range lines {
		update = binary.LittleEndian.AppendUint32(update, l.mask)
		update = binary.LittleEndian.AppendUint32(update, l.flags)
	}
	var transform []byte
	for _, l := range lines {
		if l.slot() <= 1 {
			update = append(update, l.data...)
		} else {
			transform = append(transform, l.v0, l.v1)
			transform = binary.LittleEndian.AppendUint16(transform, l.v2)
			transform = append(transform, l.data...)
		}
	}
	return append(cs, chunk{0x30, update}, chunk{0x43, transform}), nil
}

// buildCmd02 is build_cmd_02.
func (s *Sensor) buildCmd02(mode CaptureMode) ([]byte, error) {
	if s.rom.Product != 0x30 {
		return nil, fmt.Errorf("%w: ROM product 0x%02x", ErrUnsupportedSensor, s.rom.Product)
	}
	cs, err := splitChunks(s.prog)
	if err != nil {
		return nil, err
	}
	if cs, err = s.lineUpdateType1(mode, cs); err != nil {
		return nil, err
	}
	reqLines := 0
	if mode == ModeCalibrate {
		// "TODO: figure out how this is actually calculated"
		reqLines = s.typ.CalibrationFrames*s.linesPerFrame + 1
	}
	out := []byte{0x02}
	out = binary.LittleEndian.AppendUint16(out, uint16(s.typ.BytesPerLine))
	out = binary.LittleEndian.AppendUint16(out, uint16(reqLines))
	return append(out, mergeChunks(cs)...), nil
}

// --- calibration ---

// average is the interleaved branch of the reference's average(), the
// one type 0x199 takes: skip the first frame, then average each group of
// interleaved lines column by column.
func (s *Sensor) average(raw []byte) ([]byte, error) {
	bpl := s.typ.BytesPerLine
	frame := s.linesPerFrame * bpl
	interleave := s.linesPerFrame / s.typ.LinesPerCalibrationData
	if interleave <= 1 || s.typ.CalibrationFrames <= 1 || s.linesPerFrame%interleave != 0 {
		return nil, errors.New("calibration: only the interleaved, multi-frame average is ported")
	}
	if len(raw) < 2*frame {
		return nil, fmt.Errorf("calibration: %d bytes of frame data, need %d: %w", len(raw), 2*frame, ErrShortReply)
	}
	f := raw[frame : 2*frame]
	out := make([]byte, 0, frame/interleave)
	for g := 0; g < len(f); g += interleave * bpl {
		for col := range bpl {
			sum := 0
			for l := range interleave {
				sum += int(f[g+l*bpl+col])
			}
			out = append(out, byte(sum/interleave))
		}
	}
	return out, nil
}

func clip(x int) byte {
	return byte(int8(max(-128, min(127, x))))
}

// scale maps a raw calibration byte to a signed correction. The factor
// "depends on a device"; this is the reference's.
func scale(x byte) byte {
	return clip((int(x) - 0x80) * 10 / 0x22)
}

// processCalibration is process_calibration_results: scale the averaged
// frame (leaving each line's first 8 bytes alone) and add it, as clipped
// signed bytes, to what earlier iterations accumulated.
func (s *Sensor) processCalibration(cooked []byte) {
	bpl := s.typ.BytesPerLine
	frame := append([]byte(nil), cooked...)
	for l := 0; l < len(frame); l += bpl {
		for i := l + 8; i < min(l+bpl, len(frame)); i++ {
			frame[i] = scale(frame[i])
		}
	}
	if len(s.calib) == 0 {
		s.calib = frame
		return
	}
	// zip() in the reference stops at the shorter side, line by line.
	var out []byte
	for l := 0; l < len(s.calib) && l < len(frame); l += bpl {
		ll := s.calib[l:min(l+bpl, len(s.calib))]
		rr := frame[l:min(l+bpl, len(frame))]
		line := append([]byte(nil), ll[:min(8, len(ll))]...)
		for i := 8; i < len(ll) && i < len(rr); i++ {
			line = append(line, clip(int(int8(ll[i]))+int(int8(rr[i]))))
		}
		out = append(out, line...)
	}
	s.calib = out
}

// Partition 6 holds the "clean slate": a blank capture the sensor uses
// for after-capture adjustment, with a header that lets the host check it.
const (
	PartitionCalibration = 0x06
	cleanSlateMagic      = 0x5002
	cleanSlateHdrLen     = 0x44
)

// makeCleanSlate frames a blank frame: magic, length, SHA-256, 32 zero
// bytes, then u16 length, the frame and a u16 zero of unknown purpose.
func makeCleanSlate(frame []byte) []byte {
	inner := binary.LittleEndian.AppendUint16(nil, uint16(len(frame)))
	inner = append(inner, frame...)
	inner = append(inner, 0, 0)
	h := sha256.Sum256(inner)
	out := binary.LittleEndian.AppendUint16(nil, cleanSlateMagic)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(inner)))
	return concat(out, h[:], make([]byte, 0x20), inner)
}

// readFlashAll reads size bytes at start in partition, in the
// reference's 4 KiB reads.
func readFlashAll(c Commander, partition uint8, start, size uint32) ([]byte, error) {
	var out []byte
	for addr := start; addr < start+size; addr += 0x1000 {
		b, err := ReadFlash(c, partition, addr, 0x1000)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	if uint32(len(out)) < size {
		return nil, fmt.Errorf("read flash: %d of %d bytes: %w", len(out), size, ErrShortReply)
	}
	return out[:size], nil
}

// cleanSlateValid is check_clean_slate: partition 6 holds a framed blank
// frame whose hash matches.
func (s *Sensor) cleanSlateValid() (bool, error) {
	hdr, err := ReadFlash(s.sess, PartitionCalibration, 0, cleanSlateHdrLen)
	if err != nil {
		return false, err
	}
	if len(hdr) < cleanSlateHdrLen || binary.LittleEndian.Uint16(hdr) != cleanSlateMagic {
		return false, nil
	}
	n := uint32(binary.LittleEndian.Uint16(hdr[2:]))
	if !allZero(hdr[0x24:0x44]) {
		s.sess.link.log.Warn("unexpected contents in the calibration partition")
		return false, nil
	}
	img, err := readFlashAll(s.sess, PartitionCalibration, cleanSlateHdrLen, n)
	if err != nil {
		return false, err
	}
	h := sha256.Sum256(img)
	if !bytes.Equal(h[:], hdr[4:0x24]) {
		s.sess.link.log.Warn("calibration partition hash mismatch")
		return false, nil
	}
	return true, nil
}

// persistCleanSlate is persist_clean_slate: leave the partition alone if
// it already holds this header, otherwise erase it if written and write.
func (s *Sensor) persistCleanSlate(cs []byte) error {
	start, err := ReadFlash(s.sess, PartitionCalibration, 0, cleanSlateHdrLen)
	if err != nil {
		return err
	}
	if !bytes.Equal(start, bytes.Repeat([]byte{0xff}, cleanSlateHdrLen)) {
		if bytes.Equal(cs[:cleanSlateHdrLen], start) {
			s.sess.link.log.Info("calibration partition already holds this clean slate")
			return nil
		}
		if err := EraseFlash(s.sess, PartitionCalibration); err != nil {
			return err
		}
	}
	for off := 0; off < len(cs); off += 0x1000 {
		if err := WriteFlash(s.sess, PartitionCalibration, uint32(off), cs[off:min(off+0x1000, len(cs))]); err != nil {
			return err
		}
	}
	return nil
}

// captureFrames runs a calibration capture and averages what the data
// endpoint returns.
func (s *Sensor) captureFrames() ([]byte, error) {
	cmd, err := s.buildCmd02(ModeCalibrate)
	if err != nil {
		return nil, err
	}
	if _, err := s.sess.CmdOK(cmd); err != nil {
		return nil, fmt.Errorf("calibration capture: %w", err)
	}
	raw, err := s.sess.link.ReadData()
	if err != nil {
		return nil, err
	}
	return s.average(raw)
}

// Calibrate is the reference's calibrate(). With saved calibration data
// and a valid clean slate on the flash it does nothing (unless force).
// Otherwise it runs the calibration captures, adding to whatever
// calibration data it holds as the reference does, captures a blank frame
// and stores it in partition 6. It reports whether it calibrated; the
// caller then persists CalibrationData.
func (s *Sensor) Calibrate(ctx context.Context, force bool) (bool, error) {
	if len(s.calib) > 0 && !force {
		ok, err := s.cleanSlateValid()
		if err != nil {
			return false, err
		}
		if ok {
			return false, nil
		}
		s.sess.link.log.Info("no valid clean slate on the flash, calibrating")
	}
	if force {
		s.calib = nil
	}
	for i := range s.typ.CalibrationIterations {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		s.sess.link.log.Info("calibration pass", "n", i+1, "of", s.typ.CalibrationIterations)
		frame, err := s.captureFrames()
		if err != nil {
			return false, err
		}
		s.processCalibration(frame)
	}
	s.sess.link.log.Info("capturing the clean slate")
	blank, err := s.captureFrames()
	if err != nil {
		return false, err
	}
	if err := s.persistCleanSlate(makeCleanSlate(blank)); err != nil {
		return false, fmt.Errorf("store clean slate: %w", err)
	}
	return true, nil
}
