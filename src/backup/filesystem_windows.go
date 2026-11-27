//go:build windows

package backup

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func backupDirectoryMode() os.FileMode { return 0700 }

func backupDirectoryOwner(os.FileInfo) string { return "unknown" }

func filesystemTotalBytes(path string) (int64, error) {
	total, _, _, err := filesystemSpace(path)
	return total, err
}

func filesystemSpace(path string) (int64, int64, int64, error) {
	directory, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, 0, err
	}
	var free, total uint64
	if err := windows.GetDiskFreeSpaceEx(directory, &free, &total, nil); err != nil {
		return 0, 0, 0, err
	}
	return int64(total), int64(free), int64(total - free), nil
}
