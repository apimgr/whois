package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/backup"
	"github.com/casapps/caswhois/src/config"
	"github.com/casapps/caswhois/src/update"
)

// checkStatus queries the running server's health endpoint
// Returns exit code: 0 = healthy, 1 = unhealthy/error
func checkStatus(configDir string) int {
	// Find server port from PID file or config
	port, err := findServerPort(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Query health endpoint
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot connect to server: %v\n", err)
		fmt.Fprintf(os.Stderr, "Is the server running?\n")
		return 1
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		return 1
	}

	// Parse JSON response
	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Uptime  string `json:"uptime"`
		Mode    string `json:"mode"`
	}

	if err := json.Unmarshal(body, &health); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		return 1
	}

	// Check status
	if health.Status == "healthy" {
		fmt.Printf("✓ Server is healthy\n")
		fmt.Printf("  Version: %s\n", health.Version)
		fmt.Printf("  Uptime:  %s\n", health.Uptime)
		fmt.Printf("  Mode:    %s\n", health.Mode)
		return 0
	} else {
		fmt.Printf("✗ Server is unhealthy\n")
		fmt.Printf("  Status: %s\n", health.Status)
		return 1
	}
}

// findServerPort locates the server port from config or PID file
func findServerPort(configDir string) (int, error) {
	// Try to read port from PID file first (it may contain port info)
	// Format: PID or PID:PORT
	pidFile := getPIDFilePath(configDir)
	if data, err := os.ReadFile(pidFile); err == nil {
		parts := strings.Split(strings.TrimSpace(string(data)), ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil && port > 0 {
				return port, nil
			}
		}
	}

	// Try to read port from config file
	configFile := filepath.Join(getConfigDir(configDir), "server.yml")
	if data, err := os.ReadFile(configFile); err == nil {
		// Simple YAML parsing for port line
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "port:") {
				portStr := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
				port, err := strconv.Atoi(portStr)
				if err == nil && port > 0 {
					return port, nil
				}
			}
		}
	}

	// Default: try common ports
	return 0, fmt.Errorf("cannot determine server port (no config or PID file found)")
}

// getPIDFilePath returns the PID file path
func getPIDFilePath(configDir string) string {
	dataDir := getDataDir(configDir)
	return filepath.Join(dataDir, "caswhois.pid")
}

// getConfigDir returns the config directory
func getConfigDir(configDir string) string {
	if configDir != "" {
		return configDir
	}

	// Check if running as root
	if os.Geteuid() == 0 {
		return "/etc/casapps/caswhois"
	}

	// User mode
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "casapps", "caswhois")
}

// getDataDir returns the data directory
func getDataDir(configDir string) string {
	// Check if running as root
	if os.Geteuid() == 0 {
		return "/var/lib/casapps/caswhois"
	}

	// User mode
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".local", "share", "casapps", "caswhois")
}

// handleMaintenance processes --maintenance commands (PART 22)
func handleMaintenance(cmd, configDir, dataDir string) {
	// Parse command and arguments
	args := strings.Fields(cmd)
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No maintenance command specified\n")
		fmt.Fprintf(os.Stderr, "Use: --maintenance help\n")
		os.Exit(1)
	}

	operation := args[0]

	switch operation {
	case "backup":
		if err := performBackup(configDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Backup failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Backup completed successfully")

	case "restore":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: Restore requires backup file path\n")
			fmt.Fprintf(os.Stderr, "Usage: --maintenance 'restore /path/to/backup.tar.gz'\n")
			os.Exit(1)
		}
		backupFile := args[1]
		if err := performRestore(backupFile, configDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Restore failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Restore completed successfully")

	case "help":
		fmt.Println("Maintenance Commands (PART 22):")
		fmt.Println()
		fmt.Println("  backup             Create encrypted backup of database, config, and certificates")
		fmt.Println("  restore FILE       Restore from backup file")
		fmt.Println("  help               Show this help message")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  caswhois --maintenance backup")
		fmt.Println("  caswhois --maintenance 'restore /path/to/backup.tar.gz'")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown maintenance command: %s\n", operation)
		fmt.Fprintf(os.Stderr, "Use: --maintenance help\n")
		os.Exit(1)
	}
}

// handleUpdate processes --update commands (PART 23)
func handleUpdate(cmd, binaryName string) {
	args := strings.Fields(cmd)
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No update command specified\n")
		fmt.Fprintf(os.Stderr, "Use: --update help\n")
		os.Exit(1)
	}

	operation := args[0]

	switch operation {
	case "check":
		if err := checkForUpdates(binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Update check failed: %v\n", err)
			os.Exit(1)
		}

	case "yes":
		if err := performUpdate(binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✓ Update completed successfully")
		fmt.Println("  Restart the service to apply the update")

	case "branch":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: Branch command requires channel name\n")
			fmt.Fprintf(os.Stderr, "Usage: --update 'branch stable|beta|daily'\n")
			os.Exit(1)
		}
		channel := args[1]
		if err := switchUpdateChannel(channel, binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Channel switch failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Switched to %s channel\n", channel)

	case "help":
		fmt.Println("Update Commands (PART 23):")
		fmt.Println()
		fmt.Println("  check              Check for available updates")
		fmt.Println("  yes                Download and install update")
		fmt.Println("  branch CHANNEL     Switch update channel (stable|beta|daily)")
		fmt.Println("  help               Show this help message")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  caswhois --update check")
		fmt.Println("  caswhois --update yes")
		fmt.Println("  caswhois --update 'branch beta'")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown update command: %s\n", operation)
		fmt.Fprintf(os.Stderr, "Use: --update help\n")
		os.Exit(1)
	}
}

// performBackup creates an encrypted backup (PART 22)
func performBackup(configDir, dataDir string) error {
	// Prompt for password if not provided
	password := os.Getenv("CASWHOIS_BACKUP_PASSWORD")
	if password == "" {
		fmt.Print("Enter backup password (leave empty for unencrypted): ")
		fmt.Scanln(&password)
	}

	// Get backup directory (from config or default)
	// For CLI usage, default to current directory
	backupDir := "."

	opts := &backup.BackupOptions{
		ConfigDir:   getConfigDir(configDir),
		DataDir:     getDataDir(configDir),
		OutputFile:  "", // Will be auto-generated with timestamp
		Password:    password,
		IncludeSSL:  true,  // Include SSL certificates
		IncludeData: false, // Don't include data directory (can be large)
		AdminUser:   "cli-user",
		AppVersion:  Version,
	}

	// Create backup
	if err := backup.Create(opts); err != nil {
		return fmt.Errorf("create backup: %w", err)
	}

	// Verify backup immediately (PART 22 requirement)
	fmt.Println("Verifying backup...")
	if err := backup.VerifyBackup(opts.OutputFile, password); err != nil {
		// Delete failed backup
		os.Remove(opts.OutputFile)
		return fmt.Errorf("backup verification failed: %w", err)
	}

	// Move backup to backup directory if different from current dir
	if backupDir != "." && backupDir != "" {
		os.MkdirAll(backupDir, 0755)
		newPath := filepath.Join(backupDir, filepath.Base(opts.OutputFile))
		if err := os.Rename(opts.OutputFile, newPath); err == nil {
			opts.OutputFile = newPath
		}
	}

	fmt.Printf("✓ Backup created: %s\n", opts.OutputFile)
	return nil
}

// performRestore restores from backup (PART 22)
func performRestore(backupFile, configDir, dataDir string) error {
	// Check if backup file is encrypted
	isEncrypted := strings.HasSuffix(backupFile, ".enc")

	// Prompt for password if encrypted
	password := ""
	if isEncrypted {
		password = os.Getenv("CASWHOIS_BACKUP_PASSWORD")
		if password == "" {
			fmt.Print("Enter backup password: ")
			fmt.Scanln(&password)
		}
	}

	opts := &backup.RestoreOptions{
		BackupFile: backupFile,
		Password:   password,
		ConfigDir:  getConfigDir(configDir),
		DataDir:    getDataDir(configDir),
		Force:      false,
	}

	return backup.Restore(opts)
}

// checkForUpdates checks GitHub releases for updates (PART 23)
func checkForUpdates(binaryName string) error {
	// Read update channel from config
	cfg, err := config.LoadServerConfig(getConfigDir(""))
	channel := update.ChannelStable // Default
	if err == nil && cfg.UpdateChannel != "" {
		switch cfg.UpdateChannel {
		case "stable":
			channel = update.ChannelStable
		case "beta":
			channel = update.ChannelBeta
		case "daily":
			channel = update.ChannelDaily
		}
	}

	info, err := update.CheckForUpdates(Version, channel)
	if err != nil {
		return err
	}

	if !info.Available {
		fmt.Printf("✓ You are running the latest version: %s\n", info.CurrentVersion)
		return nil
	}

	fmt.Printf("Update available!\n")
	fmt.Printf("  Current version: %s\n", info.CurrentVersion)
	fmt.Printf("  Latest version:  %s\n", info.LatestVersion)
	fmt.Printf("  Release notes:   %s\n", info.ReleaseNotes)
	fmt.Printf("\nRun '%s --update yes' to install\n", binaryName)

	return nil
}

// performUpdate downloads and installs update (PART 23)
func performUpdate(binaryName string) error {
	// Read update channel from config
	cfg, err := config.LoadServerConfig(getConfigDir(""))
	channel := update.ChannelStable // Default
	if err == nil && cfg.UpdateChannel != "" {
		switch cfg.UpdateChannel {
		case "stable":
			channel = update.ChannelStable
		case "beta":
			channel = update.ChannelBeta
		case "daily":
			channel = update.ChannelDaily
		}
	}

	fmt.Println("Checking for updates...")
	info, err := update.CheckForUpdates(Version, channel)
	if err != nil {
		return err
	}

	if !info.Available {
		fmt.Printf("Already on latest version: %s\n", Version)
		return nil
	}

	fmt.Printf("Updating from %s to %s...\n", info.CurrentVersion, info.LatestVersion)

	if err := update.PerformUpdate(Version, channel); err != nil {
		return err
	}

	// Note: PerformUpdate calls restartSelf(), so this is unreachable
	return nil
}

// switchUpdateChannel changes update channel (PART 23)
func switchUpdateChannel(channel, binaryName string) error {
	var updateChannel update.UpdateChannel
	switch channel {
	case "stable":
		updateChannel = update.ChannelStable
	case "beta":
		updateChannel = update.ChannelBeta
	case "daily":
		updateChannel = update.ChannelDaily
	default:
		return fmt.Errorf("invalid channel: %s (must be: stable, beta, or daily)", channel)
	}

	// Get config path from environment variable or use default
	configPath := os.Getenv("CASWHOIS_CONFIG_DIR")
	if configPath == "" {
		configPath = getConfigDir("")
	}

	return update.SetUpdateChannel(updateChannel, configPath)
}

