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

	"github.com/apimgr/whois/src/backup"
	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/security"
	"github.com/apimgr/whois/src/update"
)

// okMark returns ✓ when color/emoji output is enabled, or "+" when NO_COLOR is set.
func okMark() string {
	if os.Getenv("NO_COLOR") != "" {
		return "+"
	}
	return "✓"
}

// failMark returns ✗ when color/emoji output is enabled, or "x" when NO_COLOR is set.
func failMark() string {
	if os.Getenv("NO_COLOR") != "" {
		return "x"
	}
	return "✗"
}

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
		fmt.Printf("%s Server is healthy\n", okMark())
		fmt.Printf("  Version: %s\n", health.Version)
		fmt.Printf("  Uptime:  %s\n", health.Uptime)
		fmt.Printf("  Mode:    %s\n", health.Mode)
		return 0
	} else {
		fmt.Printf("%s Server is unhealthy\n", failMark())
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
		return "/etc/" + constants.InternalOrg + "/" + constants.InternalName
	}

	// User mode
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", constants.InternalOrg, constants.InternalName)
}

// getDataDir returns the data directory
func getDataDir(configDir string) string {
	// Check if running as root
	if os.Geteuid() == 0 {
		return "/var/lib/" + constants.InternalOrg + "/" + constants.InternalName
	}

	// User mode
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".local", "share", constants.InternalOrg, constants.InternalName)
}

// handleMaintenance processes --maintenance commands (PART 22)
// handleMaintenance processes --maintenance commands and returns an exit code (0 = success, 1 = error).
func handleMaintenance(cmd, configDir, dataDir string) int {
	// Parse command and arguments
	args := strings.Fields(cmd)
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No maintenance command specified\n")
		fmt.Fprintf(os.Stderr, "Use: --maintenance help\n")
		return 1
	}

	operation := args[0]

	switch operation {
	case "backup":
		if err := performBackup(configDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Backup failed: %v\n", err)
			return 1
		}
		fmt.Printf("%s Backup completed successfully\n", okMark())

	case "restore":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: Restore requires backup file path\n")
			fmt.Fprintf(os.Stderr, "Usage: --maintenance 'restore /path/to/backup.tar.gz'\n")
			return 1
		}
		backupFile := args[1]
		if err := performRestore(backupFile, configDir, dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Restore failed: %v\n", err)
			return 1
		}
		fmt.Printf("%s Restore completed successfully\n", okMark())

	case "mode":
		// --maintenance mode {production|development} — change server mode (requires token or root)
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: mode requires a value: production or development\n")
			fmt.Fprintf(os.Stderr, "Usage: --maintenance 'mode production'\n")
			return 1
		}
		newMode := args[1]
		if newMode != "production" && newMode != "development" {
			fmt.Fprintf(os.Stderr, "Error: mode must be 'production' or 'development'\n")
			return 1
		}
		cfg, err := config.LoadServerConfig(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not load config: %v\n", err)
			return 1
		}
		cfg.Mode = newMode
		if saveErr := cfg.Save(configDir); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Error: could not save config: %v\n", saveErr)
			return 1
		}
		fmt.Printf("Mode set to %s. Restart the server for the change to take effect.\n", newMode)

	case "setup":
		// --maintenance setup — reset server configuration to defaults (first-run or root only)
		if os.Getuid() != 0 {
			fmt.Fprintf(os.Stderr, "Error: Setup requires root privileges or a fresh install.\n")
			fmt.Fprintf(os.Stderr, "  To reconfigure: edit server.yml directly and restart.\n")
			fmt.Fprintf(os.Stderr, "  Or run: sudo caswhois --maintenance setup\n")
			return 1
		}
		cfg := config.Default()
		cfg.ConfigDir = configDir
		if saveErr := cfg.Save(configDir); saveErr != nil {
			fmt.Fprintf(os.Stderr, "Error: could not write config: %v\n", saveErr)
			return 1
		}
		fmt.Println("Server configuration reset to defaults.")
		fmt.Printf("Edit %s/server.yml to customize, then restart.\n", configDir)

	case "pgp":
		// --maintenance pgp <action> — manage the project-level GPG keypair (PART 11)
		return handlePGP(args[1:], configDir)

	case "--help":
		fmt.Println("Maintenance Commands:")
		fmt.Println()
		fmt.Println("  backup             Create encrypted backup of database, config, and certificates")
		fmt.Println("  restore FILE       Restore from backup file (requires auth — server token or root)")
		fmt.Println("  update             Alias for --update yes (in-place binary replacement)")
		fmt.Println("  mode MODE          Change server mode (production|development) — requires root")
		fmt.Println("  setup              Reset server configuration to defaults — requires root or first-run")
		fmt.Println("  pgp ACTION         Manage the project GPG keypair (security reports / security.txt)")
		fmt.Println("  --help             Show this help message")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  caswhois --maintenance backup")
		fmt.Println("  caswhois --maintenance 'restore /path/to/backup.tar.gz'")
		fmt.Println("  sudo caswhois --maintenance 'mode development'")
		fmt.Println("  sudo caswhois --maintenance setup")
		fmt.Println("  caswhois --maintenance 'pgp generate'")
		fmt.Println("  caswhois --maintenance 'pgp --help'")

	case "help":
		fmt.Println("Maintenance Commands:")
		fmt.Println()
		fmt.Println("  backup             Create encrypted backup of database, config, and certificates")
		fmt.Println("  restore FILE       Restore from backup file (requires auth — server token or root)")
		fmt.Println("  update             Alias for --update yes (in-place binary replacement)")
		fmt.Println("  mode MODE          Change server mode (production|development) — requires root")
		fmt.Println("  setup              Reset server configuration to defaults — requires root or first-run")
		fmt.Println("  pgp ACTION         Manage the project GPG keypair (security reports / security.txt)")
		fmt.Println("  --help             Show this help message")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  caswhois --maintenance backup")
		fmt.Println("  caswhois --maintenance 'restore /path/to/backup.tar.gz'")
		fmt.Println("  sudo caswhois --maintenance 'mode development'")
		fmt.Println("  sudo caswhois --maintenance setup")
		fmt.Println("  caswhois --maintenance 'pgp generate'")
		fmt.Println("  caswhois --maintenance 'pgp --help'")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown maintenance command: %s\n", operation)
		fmt.Fprintf(os.Stderr, "Use: --maintenance help\n")
		return 1
	}
	return 0
}

// handlePGP dispatches --maintenance pgp <action> sub-commands (AI.md PART 11).
func handlePGP(args []string, configDir string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Println("PGP Keypair Management (caswhois --maintenance pgp <action>):")
		fmt.Println()
		fmt.Println("  generate                   Generate Ed25519+Curve25519 keypair")
		fmt.Println("  rotate                     Rotate to a new keypair (old kept 30 days)")
		fmt.Println("  publish [URL...]            Publish public key to keyservers")
		fmt.Println("  export public [path]        Write public key to path (or stdout if omitted)")
		fmt.Println("  export private <path>       Decrypt and write private key to path")
		fmt.Println("  import <file>              Import private key from file")
		fmt.Println("  delete                     Delete keypair (requires confirmation)")
		fmt.Println("  --help                     Show this help")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  sudo caswhois --maintenance 'pgp generate'")
		fmt.Println("  caswhois --maintenance 'pgp export public /tmp/pubkey.asc'")
		fmt.Println("  caswhois --maintenance 'pgp publish'")
		return 0
	}

	action := args[0]

	// Load config to get installationSecret and branding info
	cfg, err := config.LoadServerConfig(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not load config: %v\n", err)
		return 1
	}

	appName := cfg.Branding.Title
	if appName == "" {
		appName = constants.InternalName
	}
	contactEmail := cfg.Contact.Security.Email

	switch action {
	case "generate":
		if security.PGPKeypairExists(configDir) {
			fmt.Fprintf(os.Stderr, "Error: keypair already exists. Use 'pgp rotate' to replace it.\n")
			return 1
		}
		if err := security.GeneratePGPKeypair(configDir, appName, contactEmail, cfg.InstallationSecret); err != nil {
			fmt.Fprintf(os.Stderr, "Error: generate keypair: %v\n", err)
			return 1
		}
		fp := security.PGPPublicKeyFingerprint(configDir)
		fmt.Printf("%s PGP keypair generated\n", okMark())
		fmt.Printf("  Fingerprint: %s\n", fp)
		fmt.Printf("  Public key:  %s/security/%s\n", configDir, security.PGPPublicKeyFile)
		fmt.Printf("  Private key: %s/security/%s (encrypted)\n", configDir, security.PGPPrivateKeyFile)

	case "rotate":
		if err := security.RotatePGPKeypair(configDir, appName, contactEmail, cfg.InstallationSecret); err != nil {
			fmt.Fprintf(os.Stderr, "Error: rotate keypair: %v\n", err)
			return 1
		}
		fp := security.PGPPublicKeyFingerprint(configDir)
		fmt.Printf("%s PGP keypair rotated\n", okMark())
		fmt.Printf("  New fingerprint: %s\n", fp)

	case "publish":
		var keyservers []string
		if len(args) > 1 {
			keyservers = args[1:]
		}
		if err := security.PublishPGPKey(configDir, keyservers); err != nil {
			fmt.Fprintf(os.Stderr, "Error: publish key: %v\n", err)
			return 1
		}
		fmt.Printf("%s PGP public key published to keyservers\n", okMark())

	case "export":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: export requires 'public' or 'private'\n")
			fmt.Fprintf(os.Stderr, "Usage: --maintenance 'pgp export public [path]'\n")
			fmt.Fprintf(os.Stderr, "       --maintenance 'pgp export private <path>'\n")
			return 1
		}
		switch args[1] {
		case "public":
			outPath := ""
			if len(args) > 2 {
				outPath = args[2]
			}
			if err := security.ExportPGPPublicKey(configDir, outPath); err != nil {
				fmt.Fprintf(os.Stderr, "Error: export public key: %v\n", err)
				return 1
			}
		case "private":
			if len(args) < 3 {
				fmt.Fprintf(os.Stderr, "Error: export private requires output path\n")
				fmt.Fprintf(os.Stderr, "Usage: --maintenance 'pgp export private /path/to/output.asc'\n")
				return 1
			}
			outPath := args[2]
			if err := security.ExportPGPPrivateKey(configDir, outPath, cfg.InstallationSecret); err != nil {
				fmt.Fprintf(os.Stderr, "Error: export private key: %v\n", err)
				return 1
			}
			fmt.Printf("%s Private key exported to %s\n", okMark(), outPath)
			fmt.Println("  WARNING: Keep this file secure — it contains your private key.")
		default:
			fmt.Fprintf(os.Stderr, "Error: export requires 'public' or 'private', got %q\n", args[1])
			return 1
		}

	case "import":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: import requires key file path\n")
			fmt.Fprintf(os.Stderr, "Usage: --maintenance 'pgp import /path/to/key.asc'\n")
			return 1
		}
		keyFile := args[1]
		if err := security.ImportPGPPrivateKey(configDir, keyFile, cfg.InstallationSecret); err != nil {
			fmt.Fprintf(os.Stderr, "Error: import key: %v\n", err)
			return 1
		}
		fp := security.PGPPublicKeyFingerprint(configDir)
		fmt.Printf("%s PGP keypair imported\n", okMark())
		fmt.Printf("  Fingerprint: %s\n", fp)

	case "delete":
		if !security.PGPKeypairExists(configDir) {
			fmt.Fprintln(os.Stderr, "Error: no keypair exists — nothing to delete")
			return 1
		}
		fmt.Println("WARNING: Deleting the PGP keypair makes in-flight encrypted security reports unrecoverable.")
		fmt.Print("Type 'delete keypair' to confirm: ")
		var confirm string
		if _, err := fmt.Fscan(os.Stdin, &confirm); err != nil || confirm != "delete" {
			fmt.Println("Aborted.")
			return 1
		}
		var confirm2 string
		if _, err := fmt.Fscan(os.Stdin, &confirm2); err != nil || confirm2 != "keypair" {
			fmt.Println("Aborted.")
			return 1
		}
		if err := security.DeletePGPKeypair(configDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error: delete keypair: %v\n", err)
			return 1
		}
		fmt.Printf("%s PGP keypair deleted\n", okMark())

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown pgp action %q\n", action)
		fmt.Fprintf(os.Stderr, "Use: --maintenance 'pgp --help'\n")
		return 1
	}
	return 0
}

// handleUpdate processes --update commands and returns an exit code (0 = success, 1 = error).
func handleUpdate(cmd, binaryName string) int {
	args := strings.Fields(cmd)
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No update command specified\n")
		fmt.Fprintf(os.Stderr, "Use: --update help\n")
		return 1
	}

	operation := args[0]

	switch operation {
	case "check":
		if err := checkForUpdates(binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Update check failed: %v\n", err)
			return 1
		}

	case "yes":
		if err := performUpdate(binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Update failed: %v\n", err)
			return 1
		}
		fmt.Printf("%s Update completed successfully\n", okMark())
		fmt.Println("  Restart the service to apply the update")

	case "branch":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: Branch command requires channel name\n")
			fmt.Fprintf(os.Stderr, "Usage: --update 'branch stable|beta|daily'\n")
			return 1
		}
		channel := args[1]
		if err := switchUpdateChannel(channel, binaryName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Channel switch failed: %v\n", err)
			return 1
		}
		fmt.Printf("%s Switched to %s channel\n", okMark(), channel)

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
		return 1
	}
	return 0
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

	// OutputFile is empty so backup.Create auto-generates a timestamped name.
	// IncludeSSL captures SSL certificates; IncludeData is false to keep CLI
	// backups small (data directory can be very large).
	opts := &backup.BackupOptions{
		ConfigDir:   getConfigDir(configDir),
		DataDir:     getDataDir(configDir),
		OutputFile:  "",
		Password:    password,
		IncludeSSL:  true,
		IncludeData: false,
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

	fmt.Printf("%s Backup created: %s\n", okMark(), opts.OutputFile)
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
	// Default to the stable channel; overridden below if server.yml configures otherwise.
	channel := update.ChannelStable
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
		fmt.Printf("%s You are running the latest version: %s\n", okMark(), info.CurrentVersion)
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
	// Default to the stable channel; overridden below if server.yml configures otherwise.
	channel := update.ChannelStable
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

