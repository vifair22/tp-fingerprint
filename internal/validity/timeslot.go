package validity

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A capture program is a list of typed chunks (u16 type, u16 length,
// body). One chunk type, the timeslot table (0x34), holds byte code the
// sensor's sequencer runs; the host patches a few instructions in it
// before every capture. The decoder below is timeslot.py's decode_insn,
// covering exactly the encodings it covers.

// Timeslot opcodes the host looks for.
const (
	tsEndOfTable = 1
	tsReturn     = 2
	tsEndOfData  = 4
	tsEnableRx   = 6
	tsCall       = 11
	tsRegWrite   = 13
)

type insn struct {
	op   int
	size int
	// For tsCall: args[1] is the destination address. For tsRegWrite:
	// args[0] is the register, args[1] the value.
	args [3]int
}

var errTruncatedInsn = errors.New("truncated timeslot instruction")

func decodeInsn(b []byte) (insn, error) {
	if len(b) == 0 {
		return insn{}, errTruncatedInsn
	}
	c := int(b[0])
	need := func(n int) error {
		if len(b) < n {
			return errTruncatedInsn
		}
		return nil
	}
	switch {
	case c <= 4:
		return insn{op: c, size: 1}, nil
	case c == 5, c == 6:
		if err := need(2); err != nil {
			return insn{}, err
		}
		return insn{op: c, size: 2, args: [3]int{int(b[1])}}, nil
	case c == 7:
		if err := need(2); err != nil {
			return insn{}, err
		}
		v := int(b[1])
		if v == 0 {
			v = 0x100
		}
		return insn{op: 7, size: 2, args: [3]int{v}}, nil
	case c&0xfe == 8:
		if err := need(2); err != nil {
			return insn{}, err
		}
		return insn{op: 8, size: 2, args: [3]int{(c&1)<<8 | int(b[1])}}, nil
	case c&0xfe == 0xa:
		if err := need(2); err != nil {
			return insn{}, err
		}
		return insn{op: 9, size: 2, args: [3]int{(c&1)<<8 | int(b[1])}}, nil
	case c&0xfc == 0xc:
		return insn{op: 10, size: 1, args: [3]int{c & 3}}, nil
	case c&0xf8 == 0x10:
		if err := need(3); err != nil {
			return insn{}, err
		}
		rep := int(b[2])
		if rep == 0 {
			rep = 0x100
		}
		return insn{op: tsCall, size: 3, args: [3]int{c & 7, int(b[1]) << 2, rep}}, nil
	case c&0xe0 == 0x20:
		return insn{op: 12, size: 1, args: [3]int{c & 0x1f}}, nil
	case c&0xc0 == 0x40:
		if err := need(3); err != nil {
			return insn{}, err
		}
		return insn{op: tsRegWrite, size: 3, args: [3]int{(c&0x3f)*4 + 0x80002000, int(b[1]) | int(b[2])<<8}}, nil
	case c&0xc0 == 0x80:
		return insn{op: 14, size: 1, args: [3]int{(c & 0x38) >> 3, c & 7}}, nil
	case c&0xc0 == 0xc0:
		if err := need(2); err != nil {
			return insn{}, err
		}
		rep := int(b[1])
		if rep == 0 {
			rep = 0x100
		}
		return insn{op: 15, size: 2, args: [3]int{(c & 0x38) >> 3, c & 7, rep}}, nil
	}
	return insn{}, fmt.Errorf("unhandled timeslot instruction 0x%02x", c)
}

// findInsn returns the offset of the nth (from 1) instruction in b that
// match accepts, decoding from the start of b as the reference does.
func findInsn(b []byte, n int, match func(insn) bool) (int, error) {
	for pc := 0; pc < len(b); {
		in, err := decodeInsn(b[pc:])
		if err != nil {
			return 0, fmt.Errorf("at 0x%x: %w", pc, err)
		}
		if match(in) {
			n--
			if n == 0 {
				return pc, nil
			}
		}
		pc += in.size
	}
	return 0, errors.New("instruction not found in the timeslot table")
}

func findNthInsn(b []byte, op, n int) (int, error) {
	return findInsn(b, n, func(in insn) bool { return in.op == op })
}

func findNthRegWrite(b []byte, reg uint32, n int) (int, error) {
	return findInsn(b, n, func(in insn) bool { return in.op == tsRegWrite && uint32(in.args[0]) == reg })
}

type chunk struct {
	typ  uint16
	data []byte
}

func splitChunks(b []byte) ([]chunk, error) {
	var out []chunk
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("capture program: %d-byte chunk header: %w", len(b), ErrShortReply)
		}
		typ, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if len(b)-4 < n {
			return nil, fmt.Errorf("capture program: chunk 0x%02x of %d bytes in %d: %w", typ, n, len(b)-4, ErrShortReply)
		}
		out = append(out, chunk{typ, append([]byte(nil), b[4:4+n]...)})
		b = b[4+n:]
	}
	return out, nil
}

func mergeChunks(cs []chunk) []byte {
	var out []byte
	for _, c := range cs {
		out = binary.LittleEndian.AppendUint16(out, c.typ)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(c.data)))
		out = append(out, c.data...)
	}
	return out
}
