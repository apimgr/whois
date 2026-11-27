package server

// Build-time variables set via -ldflags (per AI.md PART 7)
// Set during build: go build -ldflags "-X main.Version=x.y.z"
var (
	// Version is the application version (from release.txt)
	Version = "dev"

	// CommitID is the git commit hash (7 chars)
	CommitID = "unknown"

	// BuildDate is derived from the embedded build epoch at process startup.
	BuildDate = "N/A"

	// OfficialSite is the project website URL
	OfficialSite = ""
)
