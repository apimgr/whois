// Package mode defines application operating modes.
package mode

// Mode represents the application operating mode.
type AppMode string

const (
	// Production is the default mode — minimal logging, strict security.
	Production AppMode = "production"
	// Development enables verbose logging, relaxed CORS, debug endpoints.
	Development AppMode = "development"
)

// IsValid returns true if m is a recognized mode.
func IsValid(m AppMode) bool {
	switch m {
	case Production, Development:
		return true
	}
	return false
}

// String returns the string representation of the mode.
func (m AppMode) String() string {
	return string(m)
}
