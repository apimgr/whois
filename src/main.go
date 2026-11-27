package main

import (
	"os"

	"github.com/apimgr/whois/src/app"
)

func main() {
	os.Exit(app.RunCLI(os.Args[1:], app.BuildInfo{
		Version:      Version,
		CommitID:     CommitID,
		BuildEpoch:   BuildEpoch,
		BuildDate:    BuildDate,
		OfficialSite: OfficialSite,
	}))
}
