package version

import "testing"

func TestFormat(t *testing.T) {
	tests := []struct {
		sv, st, bt, want string
	}{
		{"0.1.0", "20261007.1944", "release", "0.1.0_20261007.1944.release"},
		{"", "", "", "0.0.0_unknown.dev"},
	}
	for _, tt := range tests {
		if got := format(tt.sv, tt.st, tt.bt); got != tt.want {
			t.Errorf("format(%q, %q, %q) = %q, want %q", tt.sv, tt.st, tt.bt, got, tt.want)
		}
	}
	if String() != "0.0.0_unknown.dev" {
		t.Errorf("String() = %q without ldflags", String())
	}
}
