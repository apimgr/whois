package service

import (
	"fmt"
	"os"
	"runtime"

	"github.com/apimgr/whois/src/common/constants"
)

// ServiceCommand represents a service management command
type ServiceCommand string

const (
	ServiceInstall   ServiceCommand = "install"
	ServiceUninstall ServiceCommand = "uninstall"
	ServiceDisable   ServiceCommand = "disable"
	ServiceStart     ServiceCommand = "start"
	ServiceStop      ServiceCommand = "stop"
	ServiceRestart   ServiceCommand = "restart"
	ServiceReload    ServiceCommand = "reload"
	ServiceStatus    ServiceCommand = "status"
	ServiceHelp      ServiceCommand = "help"
)

// ServiceManager provides service management functionality.
type ServiceManager struct {
	// Name is the short service name (e.g., "caswhois").
	Name string
	// DisplayName is shown in service manager UIs (e.g., "caswhois service").
	DisplayName string
	// Description is a one-line service description.
	Description string
	// BinaryPath is the absolute path to the binary the service runs.
	BinaryPath string
	// WorkingDir is the working directory used when the service starts.
	WorkingDir string
}

// NewServiceManager creates a new service manager
func NewServiceManager(name, displayName, description string) (*ServiceManager, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("getting executable path: %w", err)
	}

	return &ServiceManager{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		BinaryPath:  binaryPath,
		WorkingDir:  "/",
	}, nil
}

// Execute runs the specified service command
func (sm *ServiceManager) Execute(cmd ServiceCommand) error {
	switch cmd {
	case ServiceInstall:
		return sm.Install()
	case ServiceUninstall:
		return sm.Uninstall()
	case ServiceDisable:
		return sm.Disable()
	case ServiceStart:
		return sm.Start()
	case ServiceStop:
		return sm.Stop()
	case ServiceRestart:
		return sm.Restart()
	case ServiceReload:
		return sm.Reload()
	case ServiceStatus:
		return sm.Status()
	case ServiceHelp:
		sm.PrintHelp()
		return nil
	default:
		return fmt.Errorf("unknown service command: %s", cmd)
	}
}

// Install installs and starts the service
func (sm *ServiceManager) Install() error {
	// Check if already elevated
	if !IsElevated() {
		// Check if we can escalate
		if !CanEscalate() {
			// Cannot escalate - try user service
			fmt.Println("Installing as user service (no administrator privileges)")
			return sm.installUserService()
		}
		// Prompt for escalation
		fmt.Println("Service installation requires administrator privileges.")
		fmt.Print("Escalate? [Y/n]: ")
		var response string
		fmt.Scanln(&response)
		if response != "" && response != "y" && response != "Y" {
			return fmt.Errorf("escalation declined")
		}
		// Re-exec with elevated privileges
		return ExecElevated(os.Args)
	}

	// Install system service
	return sm.installSystemService()
}

// Uninstall removes the service and all data
func (sm *ServiceManager) Uninstall() error {
	// Confirmation required
	fmt.Println("WARNING: This will delete ALL data, configs, and the system user.")
	fmt.Print("Continue? [y/N]: ")
	var response string
	fmt.Scanln(&response)
	if response != "y" && response != "Y" {
		return fmt.Errorf("uninstall cancelled")
	}

	// Check if we need escalation
	if sm.isSystemServiceInstalled() && !IsElevated() {
		if CanEscalate() {
			fmt.Println("Service uninstallation requires administrator privileges.")
			fmt.Print("Escalate? [Y/n]: ")
			fmt.Scanln(&response)
			if response != "" && response != "y" && response != "Y" {
				return fmt.Errorf("escalation declined")
			}
			return ExecElevated(os.Args)
		}
		return fmt.Errorf("uninstall requires administrator privileges")
	}

	return sm.uninstall()
}

// Disable stops and disables the service (keeps data)
func (sm *ServiceManager) Disable() error {
	// Check if we need escalation
	if sm.isSystemServiceInstalled() && !IsElevated() {
		if CanEscalate() {
			fmt.Println("Service disable requires administrator privileges.")
			fmt.Print("Escalate? [Y/n]: ")
			var response string
			fmt.Scanln(&response)
			if response != "" && response != "y" && response != "Y" {
				return fmt.Errorf("escalation declined")
			}
			return ExecElevated(os.Args)
		}
		return fmt.Errorf("disable requires administrator privileges")
	}

	return sm.disable()
}

// Start starts the service
func (sm *ServiceManager) Start() error {
	if sm.isSystemServiceInstalled() && !IsElevated() {
		// Need escalation for system service
		return fmt.Errorf("starting system service requires administrator privileges")
	}
	return sm.start()
}

// Stop stops the service
func (sm *ServiceManager) Stop() error {
	if sm.isSystemServiceInstalled() && !IsElevated() {
		// Need escalation for system service
		return fmt.Errorf("stopping system service requires administrator privileges")
	}
	return sm.stop()
}

// Restart restarts the service
func (sm *ServiceManager) Restart() error {
	if sm.isSystemServiceInstalled() && !IsElevated() {
		// Need escalation for system service
		return fmt.Errorf("restarting system service requires administrator privileges")
	}
	return sm.restart()
}

// Reload reloads the service configuration
func (sm *ServiceManager) Reload() error {
	if sm.isSystemServiceInstalled() && !IsElevated() {
		// Need escalation for system service
		return fmt.Errorf("reloading system service requires administrator privileges")
	}
	return sm.reload()
}

// Status shows service status
func (sm *ServiceManager) Status() error {
	return sm.status()
}

// PrintHelp prints service management help
func (sm *ServiceManager) PrintHelp() {
	fmt.Println("Service management commands:")
	fmt.Println()
	fmt.Println("  start       Start the service")
	fmt.Println("  stop        Stop the service")
	fmt.Println("  restart     Restart the service")
	fmt.Println("  reload      Reload configuration without restart")
	fmt.Println()
	fmt.Println("  --install   Install, enable, and start service")
	fmt.Println("  --disable   Stop and disable service (keeps data)")
	fmt.Println("  --uninstall Stop, disable, and remove everything (keeps binary)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s --service --install\n", sm.Name)
	fmt.Printf("  %s --service start\n", sm.Name)
	fmt.Printf("  %s --service status\n", sm.Name)
	fmt.Printf("  %s --service --uninstall\n", sm.Name)
}

// isSystemServiceInstalled checks if system service is installed
func (sm *ServiceManager) isSystemServiceInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		// Check systemd
		if _, err := os.Stat("/etc/systemd/system/" + sm.Name + ".service"); err == nil {
			return true
		}
		// Check OpenRC
		if _, err := os.Stat("/etc/init.d/" + sm.Name); err == nil {
			return true
		}
		// Check runit
		if _, err := os.Stat("/etc/sv/" + sm.Name); err == nil {
			return true
		}
	case "darwin":
		// Check launchd
		if _, err := os.Stat("/Library/LaunchDaemons/io.github." + constants.InternalOrg + "." + sm.Name + ".plist"); err == nil {
			return true
		}
	case "freebsd", "openbsd", "netbsd":
		// Check rc.d
		if _, err := os.Stat("/usr/local/etc/rc.d/" + sm.Name); err == nil {
			return true
		}
	case "windows":
		// Windows service check will be in platform-specific file
		return sm.isWindowsServiceInstalled()
	}
	return false
}

// Platform-specific methods will be implemented in separate files:
// - service_install_unix.go
// - service_install_windows.go
// - service_control_unix.go
// - service_control_windows.go
