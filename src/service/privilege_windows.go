//go:build windows
// +build windows

package service

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// IsElevated returns true if running as Administrator (Windows)
func IsElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// CanEscalate checks if user can escalate via UAC (Windows)
func CanEscalate() bool {
	// If already elevated, no need to escalate
	if IsElevated() {
		return true
	}
	// On Windows, any interactive user can potentially elevate via UAC
	// Check if user is in Administrators group (can elevate)
	return isInAdminGroup()
}

// isInAdminGroup checks if user is member of Administrators group
func isInAdminGroup() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}

	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, sid) {
			return true
		}
	}
	return false
}

// ExecElevated re-executes with elevated privileges via UAC (Windows)
func ExecElevated(args []string) error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	argStr := strings.Join(args[1:], " ")
	return windows.ShellExecute(0, windows.StringToUTF16Ptr(verb),
		windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(argStr),
		windows.StringToUTF16Ptr(cwd), windows.SW_NORMAL)
}
