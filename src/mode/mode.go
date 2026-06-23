// Package mode defines application operating modes.
package mode

// Mode represents the application operating mode.
type Mode string

const (
	// Production is the default mode — minimal logging, strict security.
	Production Mode = "production"
	// Development enables verbose logging, relaxed CORS, debug endpoints.
	Development Mode = "development"
)

// IsValid returns true if m is a recognized mode.
func IsValid(m Mode) bool {
	switch m {
	case Production, Development:
		return true
	}
	return false
}

// String returns the string representation of the mode.
func (m Mode) String() string {
	return string(m)
}
