//go:build linux

package i2p

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestI2PParentDeathSignalHelper(t *testing.T) {
	if os.Getenv("I2P_PARENT_DEATH_HELPER") != "1" {
		return
	}
	child := exec.Command("/bin/sleep", "600")
	setParentDeathSignal(child)
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(os.Getenv("I2P_CHILD_PID_FILE"), []byte(fmt.Sprintf("%d\n", child.Process.Pid)), 0600); err != nil {
		os.Exit(3)
	}
	select {}
}

func TestI2PSIGKILLDoesNotOrphanManagedChild(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "child.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestI2PParentDeathSignalHelper$")
	helper.Env = append(os.Environ(), "I2P_PARENT_DEATH_HELPER=1", "I2P_CHILD_PID_FILE="+pidPath)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if helper.Process != nil {
			_ = helper.Process.Kill()
			_ = helper.Wait()
		}
	}()
	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidPath); err == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if childPID > 1 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPID < 2 {
		t.Fatal("helper did not publish managed child PID")
	}
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	for time.Now().Before(deadline) {
		if syscall.Kill(childPID, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	if syscall.Kill(childPID, 0) == nil {
		if child, err := os.FindProcess(childPID); err == nil {
			_ = child.Kill()
		}
	}
	t.Fatalf("managed child %d survived parent SIGKILL", childPID)
}
