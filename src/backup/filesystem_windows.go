//go:build windows

package backup

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func filesystemTotalBytes(path string) (int64, error) {
	directory, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var total uint64
	if err := windows.GetDiskFreeSpaceEx(directory, nil, &total, nil); err != nil {
		return 0, err
	}
	return int64(total), nil
}
