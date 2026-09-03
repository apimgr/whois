package server

// Build-time variables set via -ldflags (per AI.md PART 7)
// Set during build: go build -ldflags "-X main.Version=x.y.z"
var (
	// Version is the application version (from release.txt)
	Version = "dev"

	// CommitID is the git commit hash (7 chars)
	CommitID = "unknown"

	// BuildDate is the ISO 8601 build timestamp
	BuildDate = "unknown"

	// OfficialSite is the project website URL
	OfficialSite = "https://github.com/apimgr/whois"
)
