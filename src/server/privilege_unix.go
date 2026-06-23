//go:build !windows
// +build !windows

package server

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"
)

// dropPrivileges drops the process from root to the given unprivileged service
// account after a privileged port has already been bound (AI.md PART 23).
// It is a no-op when the process is not running as root or when no account is
// configured. The gid is set before the uid because once the uid is dropped the
// process can no longer change its gid.
func dropPrivileges(username, groupname string) error {
	// Only root can (and needs to) drop privileges.
	if syscall.Geteuid() != 0 {
		return nil
	}

	// No configured account means there is nothing to drop to.
	if username == "" {
		return nil
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("lookup service user %q: %w", username, err)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("parse uid for %q: %w", username, err)
	}

	// Resolve the target gid, preferring an explicit group over the user's
	// primary group.
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for %q: %w", username, err)
	}
	if groupname != "" {
		grp, gErr := user.LookupGroup(groupname)
		if gErr != nil {
			return fmt.Errorf("lookup service group %q: %w", groupname, gErr)
		}
		gid, gErr = strconv.Atoi(grp.Gid)
		if gErr != nil {
			return fmt.Errorf("parse gid for group %q: %w", groupname, gErr)
		}
	}

	// Restrict supplementary groups to the target group only.
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("set supplementary groups: %w", err)
	}

	// Drop the group before the user; the reverse order would fail because a
	// non-root process cannot change its gid.
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("set gid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("set uid %d: %w", uid, err)
	}

	return nil
}
