//go:build !windows

package backup

import (
	"fmt"
	"os"
	"syscall"
)

func backupDirectoryMode() os.FileMode {
	if syscall.Geteuid() == 0 {
		return 0755
	}
	return 0700
}

func backupDirectoryOwner(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Uid, stat.Gid)
	}
	return "unknown"
}

func filesystemTotalBytes(path string) (int64, error) {
	total, _, _, err := filesystemSpace(path)
	return total, err
}

func filesystemSpace(path string) (int64, int64, int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, err
	}
	blockSize := int64(stat.Bsize)
	return int64(stat.Blocks) * blockSize, int64(stat.Bavail) * blockSize, (int64(stat.Blocks) - int64(stat.Bfree)) * blockSize, nil
}
