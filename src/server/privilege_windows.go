//go:build windows
// +build windows

package server

import "github.com/apimgr/whois/src/config"

func prepareRuntimeOwnership(cfg config.ServerConfig, pidPath string) error {
	return nil
}

// dropPrivileges is a no-op on Windows, which uses a Virtual Service Account
// (already minimal-privilege) instead of dropping privileges at runtime
// (AI.md PART 23).
func dropPrivileges(username, groupname string) error {
	return nil
}
