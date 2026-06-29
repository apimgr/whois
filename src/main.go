package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/server"
	"github.com/apimgr/whois/src/service"
)

// execCommand and execLookPath are vars so tests can replace them without
// spawning real processes.
var (
	execCommand  = func(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
	execLookPath = exec.LookPath
)

// Build info - set via -ldflags at build time
var (
	Version      = "dev"
	CommitID     = "unknown"
	BuildDate    = "unknown"
	OfficialSite = ""
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run parses args and executes the appropriate command.
// It returns an exit code (0 = success, 1 = error).
// Extracted from main() so that tests can call it directly.
// knownSubcommands is the set of positional subcommands supported by the server binary
// (binary-rules.md, service-rules.md). These are checked before flag parsing so that
// both `caswhois serve` and `caswhois --version` work correctly.
var knownSubcommands = map[string]bool{
	"serve":     true,
	"migrate":   true,
	"client":    true,
	"version":   true,
	"install":   true,
	"uninstall": true,
	"start":     true,
	"stop":      true,
	"restart":   true,
	"status":    true,
}

func run(args []string) int {
	// Get actual binary name (user may have renamed it)
	binaryName := filepath.Base(os.Args[0])

	// Positional subcommand routing (binary-rules.md PART 7, service-rules.md PART 23).
	// Subcommands are checked before flag parsing so both `caswhois serve` and
	// `caswhois --version` work. Only route when the first argument is a known
	// subcommand (no leading dash).
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && knownSubcommands[args[0]] {
		return runSubcommand(args[0], binaryName, args[1:])
	}

	// Define CLI flags using a FlagSet so tests can call run() multiple times.
	fs := flag.NewFlagSet(binaryName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		showHelp       bool
		showVersion    bool
		showStatus     bool
		mode           string
		configDir      string
		dataDir        string
		cacheDir       string
		logDir         string
		backupDir      string
		pidFile        string
		address        string
		port           int
		baseURL        string
		debug          bool
		daemon         bool
		noColor        bool
		colorFlag      string
		langFlag       string
		shellCmd       string
		serviceCmd     string
		maintenanceCmd string
		updateCmd      string
	)

	fs.BoolVar(&showHelp, "help", false, "Show help message")
	fs.BoolVar(&showHelp, "h", false, "Show help message")
	fs.BoolVar(&showVersion, "version", false, "Show version information")
	fs.BoolVar(&showVersion, "v", false, "Show version information")
	fs.BoolVar(&showStatus, "status", false, "Show server status and health")
	fs.StringVar(&mode, "mode", "production", "Application mode (production|development)")
	fs.StringVar(&configDir, "config", "", "Config directory")
	fs.StringVar(&dataDir, "data", "", "Data directory")
	fs.StringVar(&cacheDir, "cache", "", "Cache directory")
	fs.StringVar(&logDir, "log", "", "Log directory")
	fs.StringVar(&backupDir, "backup", "", "Backup directory")
	fs.StringVar(&pidFile, "pid", "", "PID file path")
	fs.StringVar(&address, "address", "[::]", "Listen address (default: all interfaces)")
	fs.IntVar(&port, "port", 0, "Listen port (0 = random 64000-64999)")
	fs.StringVar(&baseURL, "baseurl", "/", "URL path prefix")
	fs.BoolVar(&debug, "debug", false, "Enable debug mode")
	fs.BoolVar(&daemon, "daemon", false, "Run as daemon (detach from terminal)")
	fs.BoolVar(&noColor, "no-color", false, "Disable color output")
	fs.StringVar(&colorFlag, "color", "auto", "Color output (auto|yes|no)")
	fs.StringVar(&langFlag, "lang", "", "Language for output (default: auto from LANG env)")
	fs.StringVar(&shellCmd, "shell", "", "Shell integration (completions|init|--help) [SHELL]")
	fs.StringVar(&serviceCmd, "service", "", "Service management (install|uninstall|disable|start|stop|restart|reload|status|help)")
	fs.StringVar(&maintenanceCmd, "maintenance", "", "Maintenance operations (backup|restore|mode|setup|update|help)")
	fs.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch|help)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// --no-color flag takes precedence; map it to the colorFlag "no" value.
	if noColor {
		colorFlag = "no"
	}

	// Apply NO_COLOR standard (PART 8): non-empty NO_COLOR env var disables colors and emojis.
	// CLI --color/--no-color flags take priority over NO_COLOR.
	useColor := colorEnabled(colorFlag)

	// Handle immediate-exit flags (AI.md PART 8)
	if showVersion {
		printVersion(binaryName, useColor)
		return 0
	}

	if showHelp {
		printHelp(binaryName)
		return 0
	}

	if showStatus {
		return checkStatus(configDir)
	}

	// Handle shell integration (completions / init)
	if shellCmd != "" {
		return handleShell(shellCmd, binaryName, fs.Args())
	}

	// langFlag is consumed by the language layer after config load.
	_ = langFlag
	// pidFile is parsed for forward compatibility; PID file path is
	// determined from OS context (PART 4), not a bare boolean flag.
	_ = pidFile

	// Handle service management
	if serviceCmd != "" {
		sm, err := service.NewServiceManager("caswhois", "caswhois service", "WHOIS lookup service")
		if err != nil {
			log.Printf("Failed to create service manager: %v", err)
			return 1
		}

		cmd := service.ServiceCommand(serviceCmd)
		if err := sm.Execute(cmd); err != nil {
			log.Printf("Service command failed: %v", err)
			return 1
		}
		return 0
	}

	// Handle maintenance operations
	if maintenanceCmd != "" {
		// AI.md PART 23: --maintenance update is an alias for --update yes
		if maintenanceCmd == "update" {
			return handleUpdate("yes", binaryName)
		}
		return handleMaintenance(maintenanceCmd, configDir, dataDir)
	}

	// Handle update operations
	if updateCmd != "" {
		// Default to "yes" if no specific command given
		if updateCmd == "true" {
			updateCmd = "yes"
		}
		return handleUpdate(updateCmd, binaryName)
	}

	// Handle daemonization (Unix only)
	if daemon {
		// Check if we should daemonize based on context
		if service.ShouldDaemonize(false, daemon, false) {
			// Check for container environment
			if service.IsContainer() {
				log.Println("Warning: Running in container, ignoring --daemon flag")
			} else if service.DetectServiceManager() != "manual" {
				log.Printf("Warning: Service manager detected (%s), ignoring --daemon flag\n", service.DetectServiceManager())
			} else {
				// Safe to daemonize
				if err := service.Daemonize(); err != nil {
					log.Printf("Failed to daemonize: %v", err)
					return 1
				}
				// Parent exits here, child continues
			}
		}
	}

	// Load configuration.
	cfg, err := loadConfig(configDir, mode, address, baseURL, port, debug)
	if err != nil {
		log.Printf("Failed to load configuration: %v", err)
		return 1
	}

	// Apply directory overrides from CLI flags (AI.md PART 8).
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if cacheDir != "" {
		cfg.CacheDir = cacheDir
	}
	if logDir != "" {
		cfg.LogDir = logDir
	}
	if backupDir != "" {
		cfg.Backup.Dir = backupDir
	}

	// Initialize database
	database, err := initDatabase(cfg)
	if err != nil {
		log.Printf("Failed to initialize database: %v", err)
		return 1
	}
	defer database.Close()

	// Initialize log file infrastructure (PART 11).
	// GetLogDir() returns the correct OS/container-specific path.
	lgr, err := logger.Open(cfg.GetLogDir())
	if err != nil {
		log.Printf("WARNING: could not open log files in %s: %v — logging to stderr only", cfg.GetLogDir(), err)
		lgr = nil
	}
	if lgr != nil {
		defer lgr.Close()
	}

	// Print startup banner
	printStartupBanner(cfg)

	// Create and start server
	srv := server.New(cfg, database, lgr)
	if err := srv.Start(); err != nil {
		log.Printf("Server error: %v", err)
		return 1
	}
	return 0
}

// runSubcommand dispatches a positional subcommand (serve, migrate, client, version,
// install, uninstall, start, stop, restart, status, update). Flags following the
// subcommand are passed in remainingArgs. Returns an exit code.
func runSubcommand(subcmd, binaryName string, remainingArgs []string) int {
	switch subcmd {
	// "serve" is the default — strip the subcommand and re-enter run() with the
	// remaining args so all server flags still work.
	case "serve":
		return run(remainingArgs)

	// "version" prints the binary version string (same as --version).
	case "version":
		printVersion(binaryName, colorEnabled("auto"))
		return 0

	// "migrate" runs database schema migrations and exits.
	case "migrate":
		return runMigrate(remainingArgs)

	// "client" launches the companion caswhois-cli binary.
	case "client":
		return launchClientBinary(remainingArgs)

	// Service management subcommands (service-rules.md PART 23, 24).
	// Each maps to the equivalent --service flag value.
	case "install":
		return runServiceSubcmd("install", remainingArgs)
	case "uninstall":
		return runServiceSubcmd("uninstall", remainingArgs)
	case "start":
		return runServiceSubcmd("start", remainingArgs)
	case "stop":
		return runServiceSubcmd("stop", remainingArgs)
	case "restart":
		return runServiceSubcmd("restart", remainingArgs)

	// "status" shows server health (same as --status).
	case "status":
		return checkStatus("")

	}

	fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcmd)
	fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", binaryName)
	return 1
}

// runMigrate runs database schema migrations (migrate subcommand).
func runMigrate(args []string) int {
	// Parse optional --config flag for database location.
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configDir := fs.String("config", "", "Config directory")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	cfg, err := loadConfig(*configDir, "production", "", "/", 0, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}

	database, err := initDatabase(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		return 1
	}
	defer database.Close()

	fmt.Println("Database migrations applied successfully.")
	return 0
}

// launchClientBinary execs the caswhois-cli binary from PATH (client subcommand).
func launchClientBinary(args []string) int {
	// Search PATH for caswhois-cli.
	cliPath, err := findClientBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: caswhois-cli not found in PATH: %v\n", err)
		fmt.Fprintf(os.Stderr, "Install caswhois-cli and ensure it is in your PATH.\n")
		return 1
	}

	// Use os/exec to launch the client, inheriting stdin/stdout/stderr.
	cmd := execCommand(cliPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// ExitError carries the client's exit code.
		if exitErr, ok := err.(interface{ ExitCode() int }); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// findClientBinary locates the caswhois-cli binary in PATH.
func findClientBinary() (string, error) {
	return execLookPath("caswhois-cli")
}

// runServiceSubcmd routes a service management subcommand to the service manager.
func runServiceSubcmd(cmd string, _ []string) int {
	sm, err := service.NewServiceManager("caswhois", "caswhois service", "WHOIS lookup service")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create service manager: %v\n", err)
		return 1
	}
	if err := sm.Execute(service.ServiceCommand(cmd)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: service %s failed: %v\n", cmd, err)
		return 1
	}
	return 0
}


// colorEnabled returns whether color output is enabled, respecting PART 8 priority order:
// 1. CLI --color flag  2. NO_COLOR env var  3. Auto-detect (TTY)
// "yes"/"always" force color on regardless of NO_COLOR; "no"/"never" force off.
func colorEnabled(flag string) bool {
	switch flag {
	case "yes", "always":
		return true
	case "no", "never":
		return false
	}
	// auto: respect NO_COLOR and TERM=dumb (PART 7), then TTY
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	// Check if stdout is a TTY (simple heuristic — no extra deps)
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func printVersion(binaryName string, useColor bool) {
	// Format: {name} version {version} ({commit}) built on {date} for {os}/{arch}
	// Matches binary-rules.md §"--version Output Format (EXACT)".
	fmt.Printf("%s version %s (%s) built on %s for %s/%s\n",
		binaryName, Version, CommitID, BuildDate, runtime.GOOS, runtime.GOARCH)
	_ = useColor
}

// handleShell prints shell completion scripts or init commands (PART 8)
func handleShell(cmd, binaryName string, args []string) int {
	shell := ""
	if len(args) > 0 {
		shell = args[0]
	}
	if shell == "" {
		// Auto-detect from SHELL env
		shellEnv := os.Getenv("SHELL")
		if shellEnv != "" {
			shell = filepath.Base(shellEnv)
		}
	}

	switch cmd {
	case "completions":
		return printShellCompletions(binaryName, shell)
	case "init":
		return printShellInit(binaryName, shell)
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell command: %s\n", cmd)
		fmt.Fprintf(os.Stderr, "Usage: %s --shell {completions|init} [SHELL]\n", binaryName)
		return 1
	}
}

func printShellCompletions(binaryName, shell string) int {
	switch shell {
	case "bash":
		fmt.Printf("# bash completions for %s\n", binaryName)
		fmt.Printf("complete -W '--help --version --status --mode --config --data --cache --log --backup --pid --address --port --baseurl --daemon --debug --color --lang --shell --service --maintenance --update' %s\n", binaryName)
	case "zsh":
		fmt.Printf("# zsh completions for %s — source this file\n", binaryName)
		fmt.Printf("compdef _%s %s\n", binaryName, binaryName)
		fmt.Printf("_%s() { _arguments '--help[Show help]' '--version[Show version]' '--status[Show status]' '--config[Config directory]:dir:_files -/' '--data[Data directory]:dir:_files -/' '--port[Port]:port:' '--debug[Debug mode]' '--daemon[Daemonize]' }\n", binaryName)
	case "fish":
		fmt.Printf("# fish completions for %s\n", binaryName)
		fmt.Printf("complete -c %s -l help -d 'Show help'\n", binaryName)
		fmt.Printf("complete -c %s -l version -d 'Show version'\n", binaryName)
		fmt.Printf("complete -c %s -l status -d 'Show status'\n", binaryName)
		fmt.Printf("complete -c %s -l config -d 'Config directory' -r\n", binaryName)
		fmt.Printf("complete -c %s -l data -d 'Data directory' -r\n", binaryName)
		fmt.Printf("complete -c %s -l port -d 'Listen port' -r\n", binaryName)
		fmt.Printf("complete -c %s -l debug -d 'Debug mode'\n", binaryName)
		fmt.Printf("complete -c %s -l daemon -d 'Daemonize'\n", binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		return 1
	}
	return 0
}

func printShellInit(binaryName, shell string) int {
	switch shell {
	case "bash":
		fmt.Printf("source <(%s --shell completions bash)\n", binaryName)
	case "zsh":
		fmt.Printf("source <(%s --shell completions zsh)\n", binaryName)
	case "fish":
		fmt.Printf("%s --shell completions fish | source\n", binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		return 1
	}
	return 0
}

func printHelp(binaryName string) {
	fmt.Printf("%s - WHOIS lookup service\n\n", binaryName)
	fmt.Printf("Usage:\n")
	fmt.Printf("  %s [flags]\n\n", binaryName)
	fmt.Printf("Information:\n")
	fmt.Printf("  -h, --help                        Show this help message\n")
	fmt.Printf("  -v, --version                     Show version information\n")
	fmt.Printf("      --status                      Show server status and health\n\n")
	fmt.Printf("Shell Integration:\n")
	fmt.Printf("      --shell completions [SHELL]   Print shell completions\n")
	fmt.Printf("      --shell init [SHELL]          Print shell init command\n\n")
	fmt.Printf("Server Configuration:\n")
	fmt.Printf("      --mode MODE                   Application mode (production|development)\n")
	fmt.Printf("      --config DIR                  Config directory\n")
	fmt.Printf("      --data DIR                    Data directory\n")
	fmt.Printf("      --cache DIR                   Cache directory\n")
	fmt.Printf("      --log DIR                     Log directory\n")
	fmt.Printf("      --backup DIR                  Backup directory\n")
	fmt.Printf("      --pid FILE                    PID file path\n")
	fmt.Printf("      --address ADDR                Listen address (default: 0.0.0.0)\n")
	fmt.Printf("      --port PORT                   Listen port (default: random 64000-64999)\n")
	fmt.Printf("      --baseurl PATH                URL path prefix (default: /)\n")
	fmt.Printf("      --daemon                      Run as daemon (detach from terminal)\n")
	fmt.Printf("      --debug                       Enable debug mode\n")
	fmt.Printf("      --color {auto|yes|no}         Color output (default: auto)\n")
	fmt.Printf("      --lang CODE                   Language for output (default: auto)\n\n")
	fmt.Printf("Service Management:\n")
	fmt.Printf("      --service CMD                 Service management (install|uninstall|start|stop|restart|reload|status|help)\n\n")
	fmt.Printf("Maintenance:\n")
	fmt.Printf("      --maintenance CMD             Maintenance operations (backup|restore|mode|setup|update|help)\n\n")
	fmt.Printf("Update:\n")
	fmt.Printf("      --update [CMD]                Check/perform updates (check|yes|branch|help)\n\n")
	fmt.Printf("Run '%s <command> --help' for detailed help on any command.\n", binaryName)
}

func loadConfig(configDir, mode, address, baseURL string, port int, debug bool) (*config.ServerConfig, error) {
	var cfg *config.ServerConfig
	var err error

	// Determine config directory if not specified
	if configDir == "" {
		configDir = getDefaultConfigDir()
	}

	// Load config from file or use defaults
	cfg, err = config.LoadServerConfig(configDir)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Apply platform-specific directory defaults when not set in config (AI.md PART 4).
	// CLI flag overrides are applied after this block.
	if cfg.DataDir == "" {
		cfg.DataDir = getDefaultDataDir()
	}
	if cfg.LogDir == "" {
		cfg.LogDir = getDefaultLogDir()
	}
	if cfg.Backup.Dir == "" {
		cfg.Backup.Dir = getDefaultBackupDir()
	}

	// Override with CLI flags (highest priority per AI.md PART 5 precedence).
	if mode != "" {
		cfg.Mode = mode
	}
	if address != "" {
		cfg.Address = address
	}
	if port > 0 {
		cfg.Port = port
	}
	if debug {
		cfg.Debug = true
	}
	if baseURL != "" && baseURL != "/" {
		cfg.BaseURL = baseURL
	}

	// Set random port if not specified
	if cfg.Port == 0 {
		cfg.Port = 64000 + (os.Getpid() % 1000)
	}

	return cfg, nil
}

func initDatabase(cfg *config.ServerConfig) (*db.DB, error) {
	// Get database configuration
	driver, url, path := cfg.GetDatabaseConfig()

	log.Printf("Initializing database (driver: %s)", driver)

	// Create database config
	dbCfg := &db.DatabaseConfig{
		Driver:   driver,
		Path:     path,
		Pool:     db.DefaultPoolConfig(),
	}

	// Parse connection string for libsql/Turso remote databases.
	if url != "" {
		// Default database name when the URL does not specify one.
		dbCfg.Name = "caswhois"

		// Extract database name from URL if present.
		if strings.Contains(url, "/") {
			parts := strings.Split(url, "/")
			if len(parts) > 0 {
				dbName := parts[len(parts)-1]
				// Remove query parameters if any
				if idx := strings.Index(dbName, "?"); idx > 0 {
					dbName = dbName[:idx]
				}
				if dbName != "" {
					dbCfg.Name = dbName
				}
			}
		}
		
		log.Printf("Using remote database: %s (database: %s)", driver, dbCfg.Name)
	} else {
		// Ensure SQLite directory exists
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		log.Printf("Using SQLite database directory: %s", path)
	}

	// Initialize database with context
	ctx := context.Background()
	database, err := db.New(ctx, dbCfg)
	if err != nil {
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	log.Printf("Database initialized successfully")
	return database, nil
}

func getDefaultConfigDir() string {
	// Container path per AI.md PART 4: /config/caswhois/
	if config.IsContainer() {
		return "/config/caswhois"
	}

	// Running as root on Linux/Unix: use system-wide path
	if os.Getuid() == 0 {
		return "/etc/apimgr/caswhois"
	}

	// Non-root user: XDG-compatible per-user config directory
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not determine home directory: %v", err)
		return "."
	}

	return filepath.Join(home, ".config", "apimgr", "caswhois")
}

// getDefaultDataDir returns the platform-specific data directory (AI.md PART 4).
func getDefaultDataDir() string {
	// Container path per AI.md PART 4: /data/caswhois/
	if config.IsContainer() {
		return "/data/caswhois"
	}

	if os.Getuid() == 0 {
		return "/var/lib/apimgr/caswhois"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "share", "apimgr", "caswhois")
}

// getDefaultLogDir returns the platform-specific log directory (AI.md PART 4).
func getDefaultLogDir() string {
	// Container path per AI.md PART 4: /data/log/caswhois/
	if config.IsContainer() {
		return "/data/log/caswhois"
	}

	if os.Getuid() == 0 {
		return "/var/log/apimgr/caswhois"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "log", "apimgr", "caswhois")
}

// getDefaultBackupDir returns the platform-specific backup directory (AI.md PART 4).
func getDefaultBackupDir() string {
	// Container path per AI.md PART 4: /data/backups/caswhois/
	if config.IsContainer() {
		return "/data/backups/caswhois"
	}

	if os.Getuid() == 0 {
		return "/mnt/Backups/apimgr/caswhois"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "share", "Backups", "apimgr", "caswhois")
}

func printStartupBanner(cfg *config.ServerConfig) {
	addr := cfg.Address
	if addr == "0.0.0.0" || addr == "[::]" || addr == "" {
		addr = "localhost"
	}

	useEmoji := os.Getenv("NO_COLOR") == ""

	webIcon, healthIcon, configIcon := "Web Interface:", "Health Check:", "Configuration:"
	if useEmoji {
		webIcon = "🌐 Web Interface:"
		healthIcon = "📋 Health Check:"
		configIcon = "🔧 Configuration:"
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   CASWHOIS %-60s║\n", Version)
	fmt.Println("║                                                                      ║")
	fmt.Println("║   Status: Running                                                    ║")
	fmt.Println("║                                                                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   %s\n", webIcon)
	fmt.Printf("║      http://%s:%d\n", addr, cfg.Port)
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   %s\n", healthIcon)
	fmt.Printf("║      http://%s:%d/server/healthz\n", addr, cfg.Port)
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   %s edit server.yml to change settings\n", configIcon)
	fmt.Println("║                                                                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

