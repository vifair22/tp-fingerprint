package server

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RemoteSession returns a check for whether a process belongs to a remote
// login session, read straight from the files logind and the kernel keep
// rather than through D-Bus. A process in a session-N.scope cgroup takes
// that session's REMOTE flag (sshd sessions have REMOTE=1). A process
// outside any session scope, such as a terminal running under the user's
// systemd instance, counts as local.
//
// Anything unreadable also counts as local. That fails open on purpose:
// a remote caller misjudged as local only waits out the timeout before
// its password prompt, since nobody remote can touch the sensor.
func RemoteSession(procRoot, runRoot string) func(pid int32) bool {
	return func(pid int32) bool {
		id := sessionOf(filepath.Join(procRoot, strconv.Itoa(int(pid)), "cgroup"))
		if id == "" {
			return false
		}
		f, err := os.Open(filepath.Join(runRoot, "systemd", "sessions", id))
		if err != nil {
			return false
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "REMOTE="); ok {
				return v == "1"
			}
		}
		return false
	}
}

// sessionOf returns the logind session id from a /proc/<pid>/cgroup
// file, or "" when the process is not in a session scope.
func sessionOf(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, elem := range strings.Split(parts[2], "/") {
			if id, ok := strings.CutPrefix(elem, "session-"); ok {
				if id, ok = strings.CutSuffix(id, ".scope"); ok && id != "" && !strings.Contains(id, "/") {
					return id
				}
			}
		}
	}
	return ""
}
