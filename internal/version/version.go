// Package version carries the build's version string. The Makefile sets
// the variables through -ldflags -X from release_version and the build
// time; a plain `go build` leaves them empty and reports a dev version.
package version

var (
	semver    string // e.g. 0.1.0
	stamp     string // YYYYMMDD.HHMM
	buildType string // release, debug, race
)

// String returns SEMVER_YYYYMMDD.HHMM.TYPE.
func String() string {
	return format(semver, stamp, buildType)
}

func format(sv, st, bt string) string {
	if sv == "" {
		sv = "0.0.0"
	}
	if st == "" {
		st = "unknown"
	}
	if bt == "" {
		bt = "dev"
	}
	return sv + "_" + st + "." + bt
}
