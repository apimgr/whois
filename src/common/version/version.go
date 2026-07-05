// Package version provides version information formatting.
package version

import (
	"fmt"
	"runtime"
)

// Info holds version information
type Info struct {
	// Name is the project/binary name
	Name string
	// Version string (e.g., "1.0.0")
	Version string
	// Commit is the git commit hash
	Commit string
	// BuildDate is the build timestamp
	BuildDate string
	// GoVersion is the Go compiler version
	GoVersion string
}

// New creates a new Info with runtime information
func New(name, version, commit, buildDate string) *Info {
	return &Info{
		Name:      name,
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
	}
}

// String returns the formatted version string per AI.md spec:
// {name} version {version} ({commit}) built on {date} for {os}/{arch}
func (v *Info) String() string {
	return fmt.Sprintf("%s version %s (%s) built on %s for %s/%s",
		v.Name, v.Version, v.Commit, v.BuildDate, runtime.GOOS, runtime.GOARCH)
}

// Short returns a short version string: {name} {version}
func (v *Info) Short() string {
	return fmt.Sprintf("%s %s", v.Name, v.Version)
}

// Full returns all version details in a multi-line format
func (v *Info) Full() string {
	return fmt.Sprintf(`%s
  Version:    %s
  Commit:     %s
  Build Date: %s
  Go Version: %s
  OS/Arch:    %s/%s`,
		v.Name, v.Version, v.Commit, v.BuildDate, v.GoVersion, runtime.GOOS, runtime.GOARCH)
}

// Map returns version info as a map
func (v *Info) Map() map[string]string {
	return map[string]string{
		"name":       v.Name,
		"version":    v.Version,
		"commit":     v.Commit,
		"build_date": v.BuildDate,
		"go_version": v.GoVersion,
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

// Platform returns the current platform as os/arch
func Platform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// GoVer returns the Go version
func GoVer() string {
	return runtime.Version()
}
