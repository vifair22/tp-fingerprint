package validity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// sensorVectors are produced by testdata/gen_sensor_vectors.py, which runs
// python-validity's own Sensor code; see that file for how to regenerate.
type sensorVectors struct {
	FactoryValues string `json:"factory_values"`
	LinesPerFrame int    `json:"lines_per_frame"`
	Uncalibrated  map[string]string
	Passes        []struct {
		Raw        string `json:"raw"`
		Average    string `json:"average"`
		CalibAfter string `json:"calib_after"`
	} `json:"passes"`
	KeyLine string `json:"key_line"`
	Bitpack struct {
		Bits   int    `json:"bits"`
		Min    int    `json:"min"`
		Packed string `json:"packed"`
	} `json:"bitpack"`
	Calibrated map[string]string
	CleanSlate struct {
		Frame  string `json:"frame"`
		Framed string `json:"framed"`
	} `json:"clean_slate"`
}

func loadSensorVectors(t *testing.T) *sensorVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/sensor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		sensorVectors
		Uncal map[string]string `json:"cmd02_uncalibrated"`
		Cal   map[string]string `json:"cmd02_calibrated"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	v := raw.sensorVectors
	v.Uncalibrated, v.Calibrated = raw.Uncal, raw.Cal
	return &v
}

// vectorSensor is a Sensor set up as the generator set up the reference's.
func vectorSensor(t *testing.T, v *sensorVectors) *Sensor {
	t.Helper()
	s := &Sensor{typ: &sensorType199, rom: RomInfo{Major: 6, Product: 0x30}, prog: captureProg199,
		factoryValues: mustHex(v.FactoryValues)}
	var err error
	if s.linesPerFrame, err = linesPerFrame(s.prog, s.typ); err != nil {
		t.Fatal(err)
	}
	if s.linesPerFrame != v.LinesPerFrame {
		t.Fatalf("lines per frame %d, reference %d", s.linesPerFrame, v.LinesPerFrame)
	}
	return s
}

var modes = map[string]CaptureMode{"CALIBRATE": ModeCalibrate, "IDENTIFY": ModeIdentify, "ENROLL": ModeEnroll}

func checkCmd02(t *testing.T, s *Sensor, want map[string]string, stage string) {
	t.Helper()
	for name, mode := range modes {
		got, err := s.buildCmd02(mode)
		if err != nil {
			t.Fatalf("%s %s: %v", stage, name, err)
		}
		if w := mustHex(want[name]); !bytes.Equal(got, w) {
			i := 0
			for i < len(got) && i < len(w) && got[i] == w[i] {
				i++
			}
			t.Errorf("%s %s: %d bytes, reference %d; first difference at 0x%x", stage, name, len(got), len(w), i)
		}
	}
}

func TestSensorMatchesReference(t *testing.T) {
	v := loadSensorVectors(t)
	s := vectorSensor(t, v)

	checkCmd02(t, s, v.Uncalibrated, "uncalibrated")

	for i, p := range v.Passes {
		avg, err := s.average(mustHex(p.Raw))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(avg) != p.Average {
			t.Fatalf("pass %d: average differs from the reference", i)
		}
		s.processCalibration(avg)
		if hex.EncodeToString(s.calib) != p.CalibAfter {
			t.Fatalf("pass %d: calibration data differs from the reference", i)
		}
	}

	if hex.EncodeToString(s.keyLine()) != v.KeyLine {
		t.Error("key line differs from the reference")
	}
	bits, lo, packed, err := bitpack(s.factoryValues)
	if err != nil || bits != v.Bitpack.Bits || int(lo) != v.Bitpack.Min || hex.EncodeToString(packed) != v.Bitpack.Packed {
		t.Errorf("bitpack: %d bits, min %d, %v", bits, lo, err)
	}

	checkCmd02(t, s, v.Calibrated, "calibrated")

	if got := makeCleanSlate(mustHex(v.CleanSlate.Frame)); hex.EncodeToString(got) != v.CleanSlate.Framed {
		t.Error("clean slate framing differs from the reference")
	}
}
