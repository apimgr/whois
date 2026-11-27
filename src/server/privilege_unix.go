//go:build !windows
// +build !windows

package server

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/apimgr/whois/src/config"
)

func prepareRuntimeOwnership(cfg config.ServerConfig, pidPath string) error {
	if syscall.Geteuid() != 0 || cfg.User == "" {
		return nil
	}
	usr, err := user.Lookup(cfg.User)
	if err != nil {
		return fmt.Errorf("lookup service user %q: %w", cfg.User, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("parse uid for %q: %w", cfg.User, err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for %q: %w", cfg.User, err)
	}
	if cfg.Group != "" {
		grp, lookupErr := user.LookupGroup(cfg.Group)
		if lookupErr != nil {
			return fmt.Errorf("lookup service group %q: %w", cfg.Group, lookupErr)
		}
		gid, err = strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("parse gid for group %q: %w", cfg.Group, err)
		}
	}
	paths := []string{
		cfg.ConfigDir, cfg.DataDir, cfg.CacheDir, cfg.GetLogDir(), cfg.GetBackupDir(),
		cfg.GetDatabaseDir(),
		filepath.Join(cfg.ConfigDir, "tor"), filepath.Join(cfg.ConfigDir, "i2p"),
		filepath.Join(cfg.DataDir, "tor", "site"), filepath.Join(cfg.DataDir, "i2p", "site"),
	}
	if pidPath != "" {
		paths = append(paths, filepath.Dir(pidPath))
	}
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if !filepath.IsAbs(path) || path == string(filepath.Separator) {
			return fmt.Errorf("refusing unsafe runtime directory %q", path)
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		if err := os.MkdirAll(path, 0750); err != nil {
			return fmt.Errorf("create runtime directory %s: %w", path, err)
		}
		err := filepath.WalkDir(path, func(entryPath string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if err := os.Chown(entryPath, uid, gid); err != nil {
				return fmt.Errorf("set runtime ownership on %s: %w", entryPath, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

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
