package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/casapps/caswhois/src/admin"
	"github.com/casapps/caswhois/src/config"
	"github.com/casapps/caswhois/src/db"
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
		showHelp        bool
		showVersion     bool
		showStatus      bool
		mode            string
		configDir       string
		dataDir         string
		logDir          string
		address         string
		port            int
		debug           bool
		daemon          bool
		serviceCmd      string
		maintenanceCmd  string
		updateCmd       string
	)

	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.BoolVar(&showVersion, "v", false, "Show version information")
	flag.BoolVar(&showStatus, "status", false, "Show server status and health")
	flag.StringVar(&mode, "mode", "production", "Application mode (production|development)")
	flag.StringVar(&configDir, "config", "", "Config directory")
	flag.StringVar(&dataDir, "data", "", "Data directory")
	flag.StringVar(&logDir, "log", "", "Log directory")
	flag.StringVar(&address, "address", "127.0.0.1", "Listen address")
	flag.IntVar(&port, "port", 0, "Listen port (0 = random 64000-64999)")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode")
	flag.BoolVar(&daemon, "daemon", false, "Run as daemon (detach from terminal)")
	flag.StringVar(&serviceCmd, "service", "", "Service management (install|uninstall|disable|start|stop|restart|reload|status|help)")
	flag.StringVar(&maintenanceCmd, "maintenance", "", "Maintenance operations (backup|restore|help)")
	flag.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch|help)")

	flag.Parse()

	// Handle immediate-exit flags (AI.md PART 8)
	if showVersion {
		printVersion(binaryName)
		os.Exit(0)
	}

	if showHelp {
		printHelp(binaryName)
		os.Exit(0)
	}

	if showStatus {
		os.Exit(checkStatus(configDir))
	}

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

	// Load configuration
	cfg, err := loadConfig(configDir, mode, address, port, debug)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	database, err := initDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Handle first-run setup
	ctx := context.Background()
	if err := handleFirstRun(ctx, cfg, database); err != nil {
		log.Fatalf("Failed to handle first run: %v", err)
	}

	// Create and start server
	srv := server.New(cfg, database)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func printVersion(binaryName string) {
	fmt.Printf("%s version %s\n", binaryName, Version)
	fmt.Printf("Commit: %s\n", CommitID)
	fmt.Printf("Built: %s\n", BuildDate)
	fmt.Printf("Site: %s\n", OfficialSite)
}

func printHelp(binaryName string) {
	fmt.Printf("%s - WHOIS lookup service\n\n", binaryName)
	fmt.Printf("Usage:\n")
	fmt.Printf("  %s [flags]\n\n", binaryName)
	fmt.Printf("Information:\n")
	fmt.Printf("  -h, --help          Show this help message\n")
	fmt.Printf("  -v, --version       Show version information\n")
	fmt.Printf("      --status        Show server status and health (exit 0=healthy, 1=unhealthy)\n\n")
	fmt.Printf("Server Configuration:\n")
	fmt.Printf("      --mode MODE     Application mode (production|development)\n")
	fmt.Printf("      --config DIR    Config directory\n")
	fmt.Printf("      --data DIR      Data directory\n")
	fmt.Printf("      --log DIR       Log directory\n")
	fmt.Printf("      --address ADDR  Listen address (default: 127.0.0.1)\n")
	fmt.Printf("      --port PORT     Listen port (default: random 64000-64999)\n")
	fmt.Printf("      --daemon        Run as daemon (detach from terminal)\n")
	fmt.Printf("      --debug         Enable debug mode\n\n")
	fmt.Printf("Service Management:\n")
	fmt.Printf("      --service CMD   Service operations (install|uninstall|start|stop|restart|reload|status|help)\n\n")
	fmt.Printf("Maintenance:\n")
	fmt.Printf("      --maintenance CMD  Maintenance operations (backup|restore|help)\n")
	fmt.Printf("                         backup: Create encrypted backup\n")
	fmt.Printf("                         restore FILE: Restore from backup file\n\n")
	fmt.Printf("Update:\n")
	fmt.Printf("      --update CMD    Update operations (check|yes|branch|help)\n")
	fmt.Printf("                      check: Check for available updates\n")
	fmt.Printf("                      yes: Download and install update\n")
	fmt.Printf("                      branch NAME: Switch update channel (stable|beta|daily)\n\n")
	fmt.Printf("Full CLI implementation follows AI.md PART 8\n")
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

	// Parse connection string for PostgreSQL/MySQL
	if url != "" {
		// Parse database URL (postgres://user:pass@host:port/dbname or mysql://...)
		dbCfg.Name = "caswhois" // Default database name
		
		// Extract database name from URL if present
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
	// Check if running as root (Unix) or Administrator (Windows)
	// For now, use user directory (will implement privilege detection later)
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: Could not determine home directory: %v", err)
		return "."
	}

	return filepath.Join(home, ".config", "casapps", "caswhois")
}

func handleFirstRun(ctx context.Context, cfg *config.ServerConfig, database *db.DB) error {
	// Check if this is first run
	isFirstRun, err := admin.IsFirstRun(ctx, database)
	if err != nil {
		return fmt.Errorf("check first run: %w", err)
	}

	if !isFirstRun {
		// Not first run, continue normally
		return nil
	}

	// Generate setup token
	setupToken, err := admin.GenerateSetupToken()
	if err != nil {
		return fmt.Errorf("generate setup token: %w", err)
	}

	// Store setup token in database
	if err := admin.StoreSetupToken(ctx, database, setupToken); err != nil {
		return fmt.Errorf("store setup token: %w", err)
	}

	// Display first-run banner with setup token
	printFirstRunBanner(cfg, setupToken)

	return nil
}

func printFirstRunBanner(cfg *config.ServerConfig, setupToken string) {
	// Get addresses for display
	addr := cfg.Address
	if addr == "0.0.0.0" || addr == "" {
		addr = "localhost"
	}

	adminPath := cfg.AdminPath
	if adminPath == "" {
		adminPath = "admin"
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   CASWHOIS %s                                                    ║\n", Version)
	fmt.Println("║                                                                      ║")
	fmt.Println("║   Status: Running (first run - setup available)                     ║")
	fmt.Println("║                                                                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                      ║")
	fmt.Println("║   🌐 Web Interface:                                                   ║")
	fmt.Printf("║      http://%s:%d                                         ║\n", addr, cfg.Port)
	fmt.Println("║                                                                      ║")
	fmt.Println("║   🔧 Admin Panel:                                                     ║")
	fmt.Printf("║      http://%s:%d/%s                                      ║\n", addr, cfg.Port, adminPath)
	fmt.Println("║                                                                      ║")
	fmt.Printf("║   🔑 Setup Token (use at /%s):                              ║\n", adminPath)
	fmt.Printf("║      %s                                ║\n", setupToken)
	fmt.Println("║                                                                      ║")
	fmt.Println("║   ⚠️  Save the setup token! It will not be shown again.               ║")
	fmt.Println("║                                                                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

