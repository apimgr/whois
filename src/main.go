package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/casapps/caswhois/src/config"
	"github.com/casapps/caswhois/src/db"
	"github.com/casapps/caswhois/src/logger"
	"github.com/casapps/caswhois/src/server"
	"github.com/casapps/caswhois/src/service"
)

// Build info - set via -ldflags at build time
var (
	Version      = "dev"
	CommitID     = "unknown"
	BuildDate    = "unknown"
	OfficialSite = "https://github.com/casapps/caswhois"
)

func main() {
	// Get actual binary name (user may have renamed it)
	binaryName := filepath.Base(os.Args[0])

	// Define CLI flags
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
		colorFlag      string
		langFlag       string
		shellCmd       string
		serviceCmd     string
		maintenanceCmd string
		updateCmd      string
	)

	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version information")
	flag.BoolVar(&showStatus, "status", false, "Show server status and health")
	flag.StringVar(&mode, "mode", "production", "Application mode (production|development)")
	flag.StringVar(&configDir, "config", "", "Config directory")
	flag.StringVar(&dataDir, "data", "", "Data directory")
	flag.StringVar(&cacheDir, "cache", "", "Cache directory")
	flag.StringVar(&logDir, "log", "", "Log directory")
	flag.StringVar(&backupDir, "backup", "", "Backup directory")
	flag.StringVar(&pidFile, "pid", "", "PID file path")
	flag.StringVar(&address, "address", "[::]", "Listen address (default: all interfaces)")
	flag.IntVar(&port, "port", 0, "Listen port (0 = random 64000-64999)")
	flag.StringVar(&baseURL, "baseurl", "/", "URL path prefix")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.BoolVar(&daemon, "daemon", false, "Run as daemon (detach from terminal)")
	flag.StringVar(&colorFlag, "color", "auto", "Color output (always|never|auto)")
	flag.StringVar(&langFlag, "lang", "", "Language for output (default: auto from LANG env)")
	flag.StringVar(&shellCmd, "shell", "", "Shell integration (completions|init|--help) [SHELL]")
	flag.StringVar(&serviceCmd, "service", "", "Service management (install|uninstall|disable|start|stop|restart|reload|status|help)")
	flag.StringVar(&maintenanceCmd, "maintenance", "", "Maintenance operations (backup|restore|mode|setup|update|help)")
	flag.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch|help)")

	flag.Parse()

	// Apply NO_COLOR standard (PART 8): non-empty NO_COLOR env var disables colors and emojis.
	// CLI --color flag takes priority over NO_COLOR.
	useColor := colorEnabled(colorFlag)

	// Handle immediate-exit flags (AI.md PART 8)
	if showVersion {
		printVersion(binaryName, useColor)
		os.Exit(0)
	}

	if showHelp {
		printHelp(binaryName)
		os.Exit(0)
	}

	if showStatus {
		os.Exit(checkStatus(configDir))
	}

	// Handle shell integration (completions / init)
	if shellCmd != "" {
		handleShell(shellCmd, binaryName, flag.Args())
		os.Exit(0)
	}

	// langFlag is consumed by the language layer after config load.
	_ = langFlag
	// baseURL and pidFile are placeholders for follow-up work; they are
	// parsed for forward compatibility but not yet applied to config.
	_ = baseURL
	_ = pidFile

	// Handle service management
	if serviceCmd != "" {
		sm, err := service.NewServiceManager("caswhois", "caswhois service", "WHOIS lookup service")
		if err != nil {
			log.Fatalf("Failed to create service manager: %v", err)
		}

		cmd := service.ServiceCommand(serviceCmd)
		if err := sm.Execute(cmd); err != nil {
			log.Fatalf("Service command failed: %v", err)
		}
		os.Exit(0)
	}

	// Handle maintenance operations
	if maintenanceCmd != "" {
		// AI.md PART 23: --maintenance update is an alias for --update yes
		if maintenanceCmd == "update" {
			handleUpdate("yes", binaryName)
			os.Exit(0)
		}
		handleMaintenance(maintenanceCmd, configDir, dataDir)
		os.Exit(0)
	}

	// Handle update operations  
	if updateCmd != "" {
		// Default to "yes" if no specific command given
		if updateCmd == "" || updateCmd == "true" {
			updateCmd = "yes"
		}
		handleUpdate(updateCmd, binaryName)
		os.Exit(0)
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
					log.Fatalf("Failed to daemonize: %v", err)
				}
				// Parent exits here, child continues
			}
		}
	}

	// Load configuration.
	cfg, err := loadConfig(configDir, mode, address, port, debug)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
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
		cfg.BackupDir = backupDir
	}

	// Initialize database
	database, err := initDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
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
		log.Fatalf("Server error: %v", err)
	}
}

// colorEnabled returns whether color output is enabled, respecting PART 8 priority order:
// 1. CLI --color flag  2. NO_COLOR env var  3. Auto-detect (TTY)
func colorEnabled(flag string) bool {
	switch flag {
	case "always":
		return true
	case "never":
		return false
	}
	// auto: respect NO_COLOR, then TTY
	if os.Getenv("NO_COLOR") != "" {
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
	fmt.Printf("%s version %s\n", binaryName, Version)
	fmt.Printf("Commit: %s\n", CommitID)
	fmt.Printf("Built:  %s\n", BuildDate)
	fmt.Printf("Site:   %s\n", OfficialSite)
	// Suppress unused parameter warning in older Go toolchains
	_ = useColor
}

// handleShell prints shell completion scripts or init commands (PART 8)
func handleShell(cmd, binaryName string, args []string) {
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
		printShellCompletions(binaryName, shell)
	case "init":
		printShellInit(binaryName, shell)
	default:
		fmt.Fprintf(os.Stderr, "Unknown shell command: %s\n", cmd)
		fmt.Fprintf(os.Stderr, "Usage: %s --shell {completions|init} [SHELL]\n", binaryName)
		os.Exit(1)
	}
}

func printShellCompletions(binaryName, shell string) {
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
		os.Exit(1)
	}
}

func printShellInit(binaryName, shell string) {
	switch shell {
	case "bash":
		fmt.Printf("source <(%s --shell completions bash)\n", binaryName)
	case "zsh":
		fmt.Printf("source <(%s --shell completions zsh)\n", binaryName)
	case "fish":
		fmt.Printf("%s --shell completions fish | source\n", binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		os.Exit(1)
	}
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
	fmt.Printf("      --color {always|never|auto}   Color output (default: auto)\n")
	fmt.Printf("      --lang CODE                   Language for output (default: auto)\n\n")
	fmt.Printf("Service Management:\n")
	fmt.Printf("      --service CMD                 Service management (install|uninstall|start|stop|restart|reload|status|help)\n\n")
	fmt.Printf("Maintenance:\n")
	fmt.Printf("      --maintenance CMD             Maintenance operations (backup|restore|mode|setup|update|help)\n\n")
	fmt.Printf("Update:\n")
	fmt.Printf("      --update [CMD]                Check/perform updates (check|yes|branch|help)\n\n")
	fmt.Printf("Run '%s <command> --help' for detailed help on any command.\n", binaryName)
}

func loadConfig(configDir, mode, address string, port int, debug bool) (*config.ServerConfig, error) {
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

	// Override with CLI flags
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
		return "/etc/casapps/caswhois"
	}

	// Non-root user: XDG-compatible per-user config directory
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not determine home directory: %v", err)
		return "."
	}

	return filepath.Join(home, ".config", "casapps", "caswhois")
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

