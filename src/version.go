package main

import (
	"strconv"
	"time"
)

// Build metadata variables are injected with linker flags.
var (
	Version      = "dev"
	CommitID     = "unknown"
	BuildEpoch   = "0"
	BuildDate    = "N/A"
	OfficialSite = ""
)

func init() {
	if epoch, err := strconv.ParseInt(BuildEpoch, 10, 64); err == nil && epoch > 0 {
		BuildDate = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	}
}
