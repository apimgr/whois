package app

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/logger"
	appmode "github.com/apimgr/whois/src/mode"
	"github.com/apimgr/whois/src/scheduler"
	"github.com/apimgr/whois/src/server"
	"github.com/apimgr/whois/src/service"
	castor "github.com/apimgr/whois/src/tor"
)

// execCommand and execLookPath are vars so tests can replace them without
// spawning real processes.
var (
	execCommand  = func(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
	execLookPath = exec.LookPath
)

// Build info is injected by the executable entry point.
var (
	Version      = "dev"
	CommitID     = "unknown"
	BuildEpoch   = "0"
	BuildDate    = "N/A"
	OfficialSite = ""
)

type BuildInfo struct {
	Version      string
	CommitID     string
	BuildEpoch   string
	BuildDate    string
	OfficialSite string
}

// Run configures build metadata and starts the command-line application.
func RunCLI(args []string, info BuildInfo) int {
	Version = info.Version
	CommitID = info.CommitID
	BuildEpoch = info.BuildEpoch
	BuildDate = info.BuildDate
	OfficialSite = info.OfficialSite
	server.Version = Version
	server.CommitID = CommitID
	server.BuildDate = BuildDate
	if OfficialSite != "" {
		server.OfficialSite = OfficialSite
	}
	return runCLI(args)
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
	"update":    true,
	"scheduler": true,
}

func runCLI(args []string) int {
	// Get actual binary name (user may have renamed it)
	binaryName := filepath.Base(os.Args[0])

	// Positional subcommand routing (binary-rules.md PART 7, service-rules.md PART 23).
	// Subcommands are checked before flag parsing so both `caswhois serve` and
	// `caswhois --version` work. Only route when the first argument is a known
	// subcommand (no leading dash).
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && knownSubcommands[args[0]] {
		return runSubcommand(args[0], binaryName, args[1:])
	}

	// Define CLI flags using a FlagSet so tests can call runCLI() multiple times.
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
		port           string
		baseURL        string
		debug          bool
		i2pEnabled     bool
		daemon         bool
		noColor        bool
		yesFlag        bool
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
	fs.StringVar(&mode, "mode", "", "Application mode (production|development)")
	fs.StringVar(&configDir, "config", "", "Config directory")
	fs.StringVar(&dataDir, "data", "", "Data directory")
	fs.StringVar(&cacheDir, "cache", "", "Cache directory")
	fs.StringVar(&logDir, "log", "", "Log directory")
	fs.StringVar(&backupDir, "backup", "", "Backup directory")
	fs.StringVar(&pidFile, "pid", "", "PID file path")
	fs.StringVar(&address, "address", "", "Listen address (from configuration)")
	fs.StringVar(&port, "port", "", "Listen port or HTTP,HTTPS port pair")
	fs.StringVar(&baseURL, "baseurl", "/", "URL path prefix")
	fs.BoolVar(&debug, "debug", false, "Enable debug mode")
	fs.BoolVar(&i2pEnabled, "i2p", false, "Enable I2P eepsite")
	fs.BoolVar(&daemon, "daemon", false, "Run as daemon (detach from terminal)")
	fs.BoolVar(&noColor, "no-color", false, "Disable color output")
	fs.BoolVar(&yesFlag, "yes", false, "Confirm destructive maintenance operations")
	fs.StringVar(&colorFlag, "color", "auto", "Color output (auto|yes|no)")
	fs.StringVar(&langFlag, "lang", "", "Language for output (default: auto from LANG env)")
	fs.StringVar(&shellCmd, "shell", "", "Shell integration (completions|init|--help) [SHELL]")
	fs.StringVar(&serviceCmd, "service", "", "Service management (--install|--uninstall|--disable|start|stop|restart|reload|status|--help)")
	fs.StringVar(&maintenanceCmd, "maintenance", "", "Maintenance operations (backup|restore|update|mode|setup|pgp|token|data|compliance|--help)")
	fs.StringVar(&updateCmd, "update", "", "Update operations (check|yes|branch {stable|beta|daily}|--help)")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	// --no-color flag takes precedence; map it to the colorFlag "no" value.
	if noColor {
		colorFlag = "no"
	}
	if pidFile == "" {
		pidFile = strings.TrimSpace(os.Getenv("PID_FILE"))
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
		return checkStatusWithPID(configDir, dataDir, pidFile)
	}

	// Handle shell integration (completions / init)
	if shellCmd != "" {
		return handleShell(shellCmd, binaryName, fs.Args())
	}

	// langFlag is consumed by the language layer after config load.
	_ = langFlag

	// Handle service management
	if serviceCmd != "" {
		sm, err := service.NewServiceManager(constants.InternalName, constants.InternalName+" service", "WHOIS lookup service")
		if err != nil {
			log.Printf("Failed to create service manager: %v", err)
			return 1
		}
		servicePaths := serviceUninstallPaths(configDir, dataDir, cacheDir, logDir, backupDir, pidFile)
		sm.SetUninstallPaths(servicePaths...)
		sm.SetServiceDirectories(servicePaths[:len(servicePaths)-2]...)

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
		maintenanceArgs := append(strings.Fields(maintenanceCmd), fs.Args()...)
		if len(maintenanceArgs) > 0 && maintenanceArgs[0] == "tor" {
			return handleTorMaintenance(maintenanceArgs[1:], configDir, dataDir, yesFlag)
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
	cfg, err := loadConfigWithPortSpec(configDir, mode, address, baseURL, port, debug)
	if err != nil {
		log.Printf("Failed to load configuration: %v", err)
		return 1
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "i2p" {
			cfg.I2P.Enabled = i2pEnabled
		}
	})

	// Apply mode/debug from environment first, then let the resolved config
	// (CLI flags > server.yml) win — AI.md PART 6 precedence.
	appmode.FromEnv()
	appmode.SetAppMode(cfg.Mode)
	appmode.SetDebugEnabled(cfg.IsDebug())

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
	cfg.PIDFilePath = pidFile
	if err := Run(context.Background(), cfg); err != nil {
		log.Printf("Server error: %v", err)
		return 1
	}
	return 0
}

func Run(ctx context.Context, cfg *config.ServerConfig, listeners ...net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var listener net.Listener
	if len(listeners) > 0 {
		listener = listeners[0]
	}
	database, err := initDatabase(cfg)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer func() { _ = database.Close() }()
	if err := resumeInstallationSecretRotation(ctx, database, cfg.ConfigDir); err != nil {
		return fmt.Errorf("resume installation-secret rotation: %w", err)
	}
	if err := resumeEncryptionKeyRotation(ctx, database, cfg); err != nil {
		return fmt.Errorf("resume encryption-key rotation: %w", err)
	}

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
	srv.SetPIDFilePath(cfg.PIDFilePath)
	return srv.Run(ctx, listener)
}

// runSubcommand dispatches a positional subcommand (serve, migrate, client, version,
// install, uninstall, start, stop, restart, status, update). Flags following the
// subcommand are passed in remainingArgs. Returns an exit code.
func runSubcommand(subcmd, binaryName string, remainingArgs []string) int {
	switch subcmd {
	// "serve" is the default — strip the subcommand and re-enter runCLI() with the
	// remaining args so all server flags still work.
	case "serve":
		return runCLI(remainingArgs)

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
		return runServiceSubcmd("--install", remainingArgs)
	case "uninstall":
		return runServiceSubcmd("--uninstall", remainingArgs)
	case "start":
		return runServiceSubcmd("start", remainingArgs)
	case "stop":
		return runServiceSubcmd("stop", remainingArgs)
	case "restart":
		return runServiceSubcmd("restart", remainingArgs)

	// "status" shows server health (same as --status).
	case "status":
		return checkStatus("")

	// "update" checks for or applies updates (same as --update).
	case "update":
		return runUpdateSubcmd(binaryName, remainingArgs)

	// "scheduler" manages built-in scheduler tasks (AI.md PART 18).
	case "scheduler":
		return runSchedulerSubcmd(remainingArgs)
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
	defer func() { _ = database.Close() }()

	fmt.Println("Database migrations applied successfully.")
	return 0
}

// runSchedulerSubcmd handles the "scheduler" positional subcommand
// (AI.md PART 18 CLI Commands: list, show, run, enable, disable, history).
func runSchedulerSubcmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler <list|show|run|enable|disable|history> [task-id]")
		return 1
	}
	action := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet("scheduler", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configDir := fs.String("config", "", "Config directory")
	if err := fs.Parse(rest); err != nil {
		return 1
	}
	taskArgs := fs.Args()

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
	defer func() { _ = database.Close() }()

	catchUp := time.Hour
	if cfg.Scheduler.CatchUpWindow != "" {
		if d, parseErr := time.ParseDuration(cfg.Scheduler.CatchUpWindow); parseErr == nil {
			catchUp = d
		}
	}

	sched, err := scheduler.NewWithStore(database, cfg.Scheduler.Timezone, catchUp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scheduler: %v\n", err)
		return 1
	}
	if err := sched.RegisterBuiltInTasks(); err != nil {
		fmt.Fprintf(os.Stderr, "Error registering tasks: %v\n", err)
		return 1
	}

	switch action {
	case "list":
		for _, ts := range sched.Status() {
			state := "enabled"
			if !ts.Enabled {
				state = "disabled"
			}
			fmt.Printf("%-20s %-30s %-8s %s\n", ts.ID, ts.Schedule, state, ts.LastStatus)
		}
		return 0

	case "show":
		if len(taskArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler show <task-id>")
			return 1
		}
		task, err := sched.GetTask(taskArgs[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Printf("ID:          %s\n", task.ID)
		fmt.Printf("Name:        %s\n", task.Name)
		fmt.Printf("Schedule:    %s\n", task.Schedule)
		fmt.Printf("Enabled:     %v\n", task.Enabled)
		fmt.Printf("Last run:    %s\n", task.LastRun)
		fmt.Printf("Last status: %s\n", task.LastStatus)
		if task.LastError != "" {
			fmt.Printf("Last error:  %s\n", task.LastError)
		}
		fmt.Printf("Next run:    %s\n", task.NextRun)
		fmt.Printf("Run count:   %d\n", task.RunCount)
		fmt.Printf("Fail count:  %d\n", task.FailCount)
		return 0

	case "run":
		if len(taskArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler run <task-id>")
			return 1
		}
		if err := sched.RunTaskNow(taskArgs[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Printf("Triggered task: %s\n", taskArgs[0])
		return 0

	case "enable":
		if len(taskArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler enable <task-id>")
			return 1
		}
		if err := sched.EnableTask(taskArgs[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Printf("Enabled task: %s\n", taskArgs[0])
		return 0

	case "disable":
		if len(taskArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler disable <task-id>")
			return 1
		}
		if err := sched.DisableTask(taskArgs[0]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Printf("Disabled task: %s\n", taskArgs[0])
		return 0

	case "history":
		if len(taskArgs) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler history <task-id>")
			return 1
		}
		entries, err := sched.GetTaskHistory(taskArgs[0], 20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		if len(entries) == 0 {
			fmt.Println("No history recorded for this task.")
			return 0
		}
		for _, e := range entries {
			fmt.Printf("%s  status=%-8s duration=%dms  %s\n", e.StartedAt.Format(time.RFC3339), e.Status, e.DurationMS, e.Error)
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "Unknown scheduler action: %s\n", action)
	fmt.Fprintln(os.Stderr, "Usage: caswhois scheduler <list|show|run|enable|disable|history> [task-id]")
	return 1
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

// findClientBinary locates the CLI companion binary in PATH.
func findClientBinary() (string, error) {
	return execLookPath(constants.InternalName + "-cli")
}

// runServiceSubcmd routes a service management subcommand to the service manager.
func runServiceSubcmd(cmd string, _ []string) int {
	sm, err := service.NewServiceManager(constants.InternalName, constants.InternalName+" service", "WHOIS lookup service")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create service manager: %v\n", err)
		return 1
	}
	servicePaths := serviceUninstallPaths("", "", "", "", "", "")
	sm.SetUninstallPaths(servicePaths...)
	sm.SetServiceDirectories(servicePaths[:len(servicePaths)-2]...)
	if err := sm.Execute(service.ServiceCommand(cmd)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: service %s failed: %v\n", cmd, err)
		return 1
	}
	return 0
}

// runUpdateSubcmd handles the "update" positional subcommand by parsing flags
// and routing to handleUpdate. Supports: check, yes, branch=NAME, --version X.
func runUpdateSubcmd(binaryName string, args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	versionPin := fs.String("version", "", "Pin to specific version")
	checkOnly := fs.Bool("check", false, "Check for updates without installing")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	// Default command is "check" if no positional arg and no flags provided.
	cmd := "check"
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	} else if *checkOnly {
		cmd = "check"
	} else if *versionPin != "" {
		cmd = "version=" + *versionPin
	}
	return handleUpdate(cmd, binaryName)
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
		fmt.Printf("complete -W '--help --version --status --mode --config --data --cache --log --backup --pid --address --port --baseurl --daemon --debug --i2p --color --lang --shell --service --maintenance --update' %s\n", binaryName)
	case "zsh":
		fmt.Printf("# zsh completions for %s — source this file\n", binaryName)
		fmt.Printf("compdef _%s %s\n", binaryName, binaryName)
		fmt.Printf("_%s() { _arguments '--help[Show help]' '--version[Show version]' '--status[Show status]' '--config[Config directory]:dir:_files -/' '--data[Data directory]:dir:_files -/' '--port[Port]:port:' '--debug[Debug mode]' '--i2p[Enable I2P eepsite]' '--daemon[Daemonize]' }\n", binaryName)
	case "fish":
		fmt.Printf("# fish completions for %s\n", binaryName)
		fmt.Printf("complete -c %s -l help -d 'Show help'\n", binaryName)
		fmt.Printf("complete -c %s -l version -d 'Show version'\n", binaryName)
		fmt.Printf("complete -c %s -l status -d 'Show status'\n", binaryName)
		fmt.Printf("complete -c %s -l i2p -d 'Enable I2P eepsite'\n", binaryName)
		fmt.Printf("complete -c %s -l config -d 'Config directory' -r\n", binaryName)
		fmt.Printf("complete -c %s -l data -d 'Data directory' -r\n", binaryName)
		fmt.Printf("complete -c %s -l port -d 'HTTP port or HTTP,HTTPS pair' -r\n", binaryName)
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
	fmt.Printf("      --port PORT                   Listen port or HTTP,HTTPS pair (default: random 64000-64999)\n")
	fmt.Printf("      --baseurl PATH                URL path prefix (default: /)\n")
	fmt.Printf("      --daemon                      Run as daemon (detach from terminal)\n")
	fmt.Printf("      --debug                       Enable debug mode\n")
	fmt.Printf("      --i2p[=BOOL]                  Enable I2P eepsite (also accepts --i2p=false)\n")
	fmt.Printf("      --color {auto|yes|no}         Color output (default: auto)\n")
	fmt.Printf("      --lang CODE                   Language for output (default: auto)\n\n")
	fmt.Printf("Service Management:\n")
	fmt.Printf("      --service CMD                 Service management (--install|--uninstall|--disable|start|stop|restart|reload|status|--help)\n\n")
	fmt.Printf("Maintenance:\n")
	fmt.Printf("      --maintenance CMD             Maintenance operations (backup|restore|update|mode|setup|pgp|token|data|compliance|tor|--help)\n")
	fmt.Printf("      --yes                         Confirm destructive maintenance operations\n\n")
	fmt.Printf("Update:\n")
	fmt.Printf("      --update [CMD]                Check/perform updates (check|yes|branch {stable|beta|daily}|--help)\n\n")
	fmt.Printf("Run '%s <command> --help' for detailed help on any command.\n", binaryName)
}

func loadConfig(configDir, mode, address, baseURL string, port int, debug bool) (*config.ServerConfig, error) {
	portSpec := ""
	if port > 0 {
		portSpec = strconv.Itoa(port)
	}
	return loadConfigWithPortSpec(configDir, mode, address, baseURL, portSpec, debug)
}

type torMaintenanceEnvelope struct {
	OK      bool           `json:"ok"`
	Data    map[string]any `json:"data"`
	Error   string         `json:"error"`
	Message string         `json:"message"`
}

func handleTorMaintenance(args []string, configDir, dataDir string, yes bool) int {
	filtered := args[:0]
	for _, arg := range args {
		if arg == "--yes" || arg == "-y" {
			yes = true
			continue
		}
		filtered = append(filtered, arg)
	}
	args = filtered
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Println("Tor maintenance: status | validate | restart | regenerate | vanity start|stop|apply | import-keys <path>")
		return 0
	}
	operation := args[0]
	path := "/server/tor/" + operation
	var body map[string]any
	confirmation := ""
	mutating := operation != "status" && operation != "validate"
	switch operation {
	case "status", "validate", "restart", "regenerate":
	case "vanity":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: --maintenance tor vanity <start|stop|apply>")
			return 1
		}
		action := args[1]
		args = args[2:]
		switch action {
		case "start":
			prefix, workers := stringFlag(args, "--prefix"), intFlag(args, "--workers", 0)
			if prefix == "" {
				fmt.Fprintln(os.Stderr, "Error: vanity start requires --prefix")
				return 1
			}
			path = "/server/tor/vanity/start"
			body = map[string]any{"prefix": prefix, "workers": workers}
		case "stop":
			path = "/server/tor/vanity/stop"
		case "apply":
			address := ""
			if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
				address = args[0]
			}
			confirmation = "Applying a vanity address permanently replaces the current onion address."
			path = "/server/tor/vanity/apply"
			body = map[string]any{"address": address}
		default:
			fmt.Fprintln(os.Stderr, "Error: vanity action must be start, stop, or apply")
			return 1
		}
	case "import-keys":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: --maintenance tor import-keys <absolute-key-directory>")
			return 1
		}
		if !filepath.IsAbs(args[1]) {
			fmt.Fprintln(os.Stderr, "Error: key directory path must be absolute")
			return 1
		}
		confirmation = "Importing keys permanently replaces the current onion address."
		path = "/server/tor/import-keys"
		body = map[string]any{"path": args[1]}
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown Tor operation %q\n", operation)
		return 1
	}
	if operation == "regenerate" {
		confirmation = "Regenerating permanently replaces the current onion address."
		body = map[string]any{}
	}
	if operation == "vanity" && len(body) > 0 && strings.HasSuffix(path, "/apply") {
		mutating = true
	}
	if operation == "import-keys" || operation == "regenerate" {
		mutating = true
	}
	configDir = getConfigDir(configDir)
	if dataDir == "" {
		dataDir = getDataDir(configDir)
	}
	operatorToken, tokenErr := config.ReadOperatorToken(configDir)
	if tokenErr != nil {
		fmt.Fprintf(os.Stderr, "Error: read operator token: %v\n", tokenErr)
		return 1
	}
	if !authorizeOperatorMaintenance(&config.ServerConfig{ServerToken: operatorToken}, "Tor maintenance") {
		return 1
	}
	if confirmation != "" {
		if !confirmTorAction(yes, confirmation) {
			return 1
		}
		body["confirm"] = true
	}
	port, err := findServerPort(configDir, dataDir)
	if err != nil {
		if mutating {
			fmt.Fprintln(os.Stderr, "Error: no running server detected — start the server first")
			return 1
		}
		return torMaintenanceOffline(operation, configDir, dataDir)
	}
	var requestBody io.Reader
	if body != nil {
		encoded, encodeErr := json.Marshal(body)
		if encodeErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", encodeErr)
			return 1
		}
		requestBody = strings.NewReader(string(encoded))
	}
	method := http.MethodGet
	if operation != "status" {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), requestBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		if mutating {
			fmt.Fprintln(os.Stderr, "Error: no running server detected — start the server first")
		} else {
			return torMaintenanceOffline(operation, configDir, dataDir)
		}
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	var envelope torMaintenanceEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid Tor response: %v\n", err)
		return 1
	}
	if !envelope.OK {
		if envelope.Message == "" {
			envelope.Message = envelope.Error
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", envelope.Message)
		return 1
	}
	encoded, _ := json.MarshalIndent(envelope.Data, "", "  ")
	fmt.Println(string(encoded))
	if operation == "validate" {
		if valid, ok := envelope.Data["valid"].(bool); ok && !valid {
			return 1
		}
	}
	return 0
}

func confirmTorAction(yes bool, message string) bool {
	if yes {
		return true
	}
	fmt.Fprintf(os.Stderr, "%s\nType 'yes' to continue: ", message)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || strings.TrimSpace(answer) != "yes" {
		fmt.Fprintln(os.Stderr, "Cancelled.")
		return false
	}
	return true
}

func stringFlag(args []string, name string) string {
	for i, arg := range args {
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"=")
		}
		if arg == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func intFlag(args []string, name string, fallback int) int {
	value := stringFlag(args, name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}

func torMaintenanceOffline(operation, configDir, dataDir string) int {
	switch operation {
	case "status":
		hostname, _ := os.ReadFile(filepath.Join(dataDir, "tor", "site", "hostname"))
		torrc, _ := os.ReadFile(filepath.Join(configDir, "tor", "torrc"))
		address := strings.TrimSpace(string(hostname))
		result := map[string]any{"running": false, "version": "", "bootstrap_percent": 0, "circuit_established": false, "vanity": map[string]any{"state": "idle", "candidates": []string{}}}
		if address != "" {
			result["onion_address"] = address
		}
		result["torrc_present"] = len(torrc) > 0
		encoded, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(encoded))
		return 0
	case "validate":
		cfg, err := config.LoadServerConfig(configDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		torCfg := castor.TorConfig{Binary: cfg.Tor.Binary, UseNetwork: cfg.Tor.UseNetwork, AllowUserPreference: cfg.Tor.AllowUserPreference, MaxCircuits: cfg.Tor.MaxCircuits, StartupTimeout: cfg.Tor.StartupTimeout, CircuitTimeout: cfg.Tor.CircuitTimeout, BootstrapTimeout: cfg.Tor.BootstrapTimeout, SafeLogging: cfg.Tor.SafeLogging, MaxStreamsPerCircuit: cfg.Tor.MaxStreamsPerCircuit, CloseCircuitOnStreamLimit: cfg.Tor.CloseCircuitOnStreamLimit, BandwidthRate: cfg.Tor.BandwidthRate, BandwidthBurst: cfg.Tor.BandwidthBurst, MaxMonthlyBandwidth: cfg.Tor.MaxMonthlyBandwidth, NumIntroPoints: cfg.Tor.NumIntroPoints, VirtualPort: cfg.Tor.VirtualPort}
		errors := castor.ValidateConfig(torCfg)
		encoded, _ := json.MarshalIndent(map[string]any{"valid": len(errors) == 0, "errors": errors}, "", "  ")
		fmt.Println(string(encoded))
		if len(errors) > 0 {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "Error: no running server detected — start the server first")
		return 1
	}
}

func loadConfigWithPortSpec(configDir, mode, address, baseURL, portSpec string, debug bool) (*config.ServerConfig, error) {
	var cfg *config.ServerConfig
	var err error

	// Determine config directory if not specified
	if configDir == "" {
		configDir = getDefaultConfigDir()
	}

	// Load config from file or use defaults
	// Read listener settings from the node and ordered area files before loading
	// credentials. The full loader below applies the same merged values.
	if _, err := config.LoadEarlyConfig(configDir); err != nil {
		return nil, fmt.Errorf("loading early config: %w", err)
	}
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

	// PORT and LISTEN are init-only env vars (AI.md PART 5): consulted only
	// when server.yml has no port/address set yet, before CLI flags apply.
	if cfg.Port == 0 {
		if envPort := os.Getenv("PORT"); envPort != "" {
			if h, s, p, err := parsePortSpec(envPort); err == nil {
				cfg.Port, cfg.HTTPPort, cfg.HTTPSPort = p, h, s
			}
		}
	}
	if cfg.Address == "" {
		if envListen := os.Getenv("LISTEN"); envListen != "" {
			cfg.Address = envListen
		}
	}

	// Override with CLI flags (highest priority per AI.md PART 5 precedence).
	if mode != "" {
		cfg.Mode = mode
	}

	// Invalid mode values fall back safely instead of preventing startup.
	if cfg.Mode != "" && cfg.Mode != "production" && cfg.Mode != "development" {
		log.Printf("WARN: invalid mode %q — defaulting to production", cfg.Mode)
		cfg.Mode = "production"
	}

	if address != "" {
		cfg.Address = address
	}
	if strings.TrimSpace(portSpec) != "" {
		h, s, p, parseErr := parsePortSpec(portSpec)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid port %q: %w", portSpec, parseErr)
		}
		cfg.Port, cfg.HTTPPort, cfg.HTTPSPort = p, h, s
	}
	if debug {
		cfg.Debug = true
	}
	if baseURL != "" && baseURL != "/" {
		cfg.BaseURL = baseURL
	}

	// Set random port if not specified
	if cfg.Port == 0 {
		if service.IsContainer() {
			cfg.Port = 80
		} else {
			cfg.Port = 64000 + (os.Getpid() % 1000)
		}
	}
	if cfg.HTTPPort == 0 && cfg.HTTPSPort == 0 {
		if cfg.Port == 443 {
			cfg.HTTPSPort = cfg.Port
		} else {
			cfg.HTTPPort = cfg.Port
		}
	}

	return cfg, nil
}

func parsePortSpec(spec string) (httpPort, httpsPort, primary int, err error) {
	parts := strings.Split(strings.TrimSpace(spec), ",")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, 0, fmt.Errorf("expected one port or an HTTP,HTTPS pair")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		p, parseErr := strconv.Atoi(strings.TrimSpace(part))
		if parseErr != nil || p < 1 || p > 65535 {
			return 0, 0, 0, fmt.Errorf("ports must be integers from 1 through 65535")
		}
		values[i] = p
	}
	if len(values) == 1 {
		if values[0] == 443 {
			return 0, 443, 443, nil
		}
		return values[0], 0, values[0], nil
	}
	if values[0] == values[1] {
		return 0, 0, 0, fmt.Errorf("HTTP and HTTPS ports must differ")
	}
	return values[0], values[1], values[0], nil
}

func initDatabase(cfg *config.ServerConfig) (*db.DB, error) {
	// Get database configuration
	driver, url, path := cfg.GetDatabaseConfig()

	log.Printf("Initializing database (driver: %s)", driver)

	// Create database config
	dbCfg := &db.DatabaseConfig{
		Driver: driver,
		Path:   path,
		Pool:   db.DefaultPoolConfig(),
	}

	// Parse connection string for libsql/Turso remote databases.
	if url != "" {
		dbCfg.URL = url
		dbCfg.Token = cfg.Database.Token

		// Default database name when the URL does not specify one.
		dbCfg.Name = constants.InternalName

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
	// CONFIG_DIR is an init-only env var (AI.md PART 5): consulted only when
	// no --config flag was given and no server.yml has been generated yet.
	if envDir := os.Getenv("CONFIG_DIR"); envDir != "" {
		return envDir
	}

	// Container path per AI.md PART 4: /config/caswhois/
	if config.IsContainer() {
		return "/config/caswhois"
	}

	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName)
		}
		return filepath.Join(windowsAppData(), constants.InternalOrg, constants.InternalName)
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Application Support", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			log.Printf("Warning: Could not determine home directory: %v", err)
			return "."
		}
		return filepath.Join(home, "Library", "Application Support", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/usr", "local", "etc", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			log.Printf("Warning: Could not determine home directory: %v", err)
			return "."
		}
		return filepath.Join(home, ".config", constants.InternalOrg, constants.InternalName)
	default:
		// Running as root on Linux: use system-wide path
		if os.Getuid() == 0 {
			return "/etc/" + constants.InternalOrg + "/" + constants.InternalName
		}

		// Non-root user: XDG-compatible per-user config directory
		home, err := os.UserHomeDir()
		if err != nil {
			log.Printf("Warning: Could not determine home directory: %v", err)
			return "."
		}

		return filepath.Join(home, ".config", constants.InternalOrg, constants.InternalName)
	}
}

// getDefaultDataDir returns the platform-specific data directory (AI.md PART 4).
func getDefaultDataDir() string {
	// DATA_DIR is an init-only env var (AI.md PART 5): consulted only when
	// server.yml has no data_dir set yet.
	if envDir := os.Getenv("DATA_DIR"); envDir != "" {
		return envDir
	}

	// Container path per AI.md PART 4: /data/{internal_name}/
	if config.IsContainer() {
		return "/data/" + constants.InternalName
	}

	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName, "data")
		}
		return filepath.Join(windowsLocalAppData(), constants.InternalOrg, constants.InternalName)
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Application Support", constants.InternalOrg, constants.InternalName, "data")
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, "Library", "Application Support", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "db", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "share", constants.InternalOrg, constants.InternalName)
	default:
		if os.Getuid() == 0 {
			return "/var/lib/" + constants.InternalOrg + "/" + constants.InternalName
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "share", constants.InternalOrg, constants.InternalName)
	}
}

// getDefaultLogDir returns the platform-specific log directory (AI.md PART 4).
func getDefaultLogDir() string {
	// LOG_DIR is an init-only env var (AI.md PART 5): consulted only when
	// server.yml has no log_dir set yet.
	if envDir := os.Getenv("LOG_DIR"); envDir != "" {
		return envDir
	}

	// Container path per AI.md PART 4: /data/log/{internal_name}/
	if config.IsContainer() {
		return "/data/log/" + constants.InternalName
	}

	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName, "logs")
		}
		return filepath.Join(windowsLocalAppData(), constants.InternalOrg, constants.InternalName, "logs")
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Logs", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, "Library", "Logs", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "log", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "log", constants.InternalOrg, constants.InternalName)
	default:
		if os.Getuid() == 0 {
			return "/var/log/" + constants.InternalOrg + "/" + constants.InternalName
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "log", constants.InternalOrg, constants.InternalName)
	}
}

// getDefaultBackupDir returns the platform-specific backup directory (AI.md PART 4).
func getDefaultBackupDir() string {
	// BACKUP_DIR is an init-only env var (AI.md PART 5): consulted only when
	// server.yml has no backup.dir set yet.
	if envDir := os.Getenv("BACKUP_DIR"); envDir != "" {
		return envDir
	}

	// Container path per AI.md PART 4: /data/backups/{internal_name}/
	if config.IsContainer() {
		return "/data/backups/" + constants.InternalName
	}

	switch runtime.GOOS {
	case "windows":
		if os.Getuid() == 0 {
			return filepath.Join(windowsProgramData(), "Backups", constants.InternalOrg, constants.InternalName)
		}
		return filepath.Join(windowsLocalAppData(), "Backups", constants.InternalOrg, constants.InternalName)
	case "darwin":
		if os.Getuid() == 0 {
			return filepath.Join("/Library", "Backups", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, "Library", "Backups", constants.InternalOrg, constants.InternalName)
	case "freebsd", "openbsd", "netbsd":
		if os.Getuid() == 0 {
			return filepath.Join("/var", "backups", constants.InternalOrg, constants.InternalName)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "share", "Backups", constants.InternalOrg, constants.InternalName)
	default:
		if os.Getuid() == 0 {
			return "/mnt/Backups/" + constants.InternalOrg + "/" + constants.InternalName
		}

		home, err := os.UserHomeDir()
		if err != nil {
			return "."
		}
		return filepath.Join(home, ".local", "share", "Backups", constants.InternalOrg, constants.InternalName)
	}
}

func serviceUninstallPaths(configFlag, dataFlag, cacheFlag, logFlag, backupFlag, pidFlag string) []string {
	configPath := configFlag
	if configPath == "" {
		configPath = getDefaultConfigDir()
	}
	var configured struct {
		Server struct {
			ConfigDir string `yaml:"config_dir"`
			DataDir   string `yaml:"data_dir"`
			CacheDir  string `yaml:"cache_dir"`
			LogDir    string `yaml:"log_dir"`
			Backup    struct {
				Dir string `yaml:"dir"`
			} `yaml:"backup"`
		} `yaml:"server"`
	}
	apply := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var candidate struct {
			Server struct {
				ConfigDir string `yaml:"config_dir"`
				DataDir   string `yaml:"data_dir"`
				CacheDir  string `yaml:"cache_dir"`
				LogDir    string `yaml:"log_dir"`
				Backup    struct {
					Dir string `yaml:"dir"`
				} `yaml:"backup"`
			} `yaml:"server"`
		}
		if yaml.Unmarshal(data, &candidate) == nil {
			if candidate.Server.ConfigDir != "" {
				configured.Server.ConfigDir = candidate.Server.ConfigDir
			}
			if candidate.Server.DataDir != "" {
				configured.Server.DataDir = candidate.Server.DataDir
			}
			if candidate.Server.CacheDir != "" {
				configured.Server.CacheDir = candidate.Server.CacheDir
			}
			if candidate.Server.LogDir != "" {
				configured.Server.LogDir = candidate.Server.LogDir
			}
			if candidate.Server.Backup.Dir != "" {
				configured.Server.Backup.Dir = candidate.Server.Backup.Dir
			}
		}
	}
	apply(filepath.Join(configPath, "server.yml"))
	if entries, err := os.ReadDir(filepath.Join(configPath, "yaml.d")); err == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
				apply(filepath.Join(configPath, "yaml.d", entry.Name()))
			}
		}
	}
	configPaths := []string{configPath}
	if configured.Server.ConfigDir != "" {
		configPaths = append(configPaths, configured.Server.ConfigDir)
	}
	dataPath := configured.Server.DataDir
	if dataPath == "" {
		dataPath = getDefaultDataDir()
	}
	cachePath := configured.Server.CacheDir
	if cachePath == "" {
		cachePath = defaultCacheDir()
	}
	logPath := configured.Server.LogDir
	if logPath == "" {
		logPath = getDefaultLogDir()
	}
	backupPath := configured.Server.Backup.Dir
	if backupPath == "" {
		backupPath = getDefaultBackupDir()
	}
	if dataFlag != "" {
		dataPath = dataFlag
	}
	if cacheFlag != "" {
		cachePath = cacheFlag
	}
	if logFlag != "" {
		logPath = logFlag
	}
	if backupFlag != "" {
		backupPath = backupFlag
	}
	pidPath := pidFlag
	if pidPath == "" {
		if os.Geteuid() == 0 {
			pidPath = filepath.Join("/var/run", constants.InternalOrg, constants.InternalName, constants.InternalName+".pid")
		} else {
			pidPath = filepath.Join(dataPath, constants.InternalName+".pid")
		}
	}
	paths := []string{configPath, dataPath, cachePath, logPath, backupPath}
	paths = append(paths, configPaths[1:]...)
	markerPath := filepath.Join(filepath.Dir(dataPath), "."+constants.InternalName+"-service-account-created")
	return append(paths, pidPath, markerPath)
}

func defaultCacheDir() string {
	if value := os.Getenv("CACHE_DIR"); value != "" {
		return value
	}
	if config.IsContainer() {
		return "/cache/" + constants.InternalName
	}
	if os.Getuid() != 0 {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, ".cache", constants.InternalOrg, constants.InternalName)
		}
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(windowsProgramData(), constants.InternalOrg, constants.InternalName, "cache")
	case "darwin":
		return filepath.Join("/Library", "Caches", constants.InternalOrg, constants.InternalName)
	default:
		return "/var/cache/" + constants.InternalOrg + "/" + constants.InternalName
	}
}

// windowsProgramData returns %ProgramData% (system-wide writable data), falling
// back to the documented default if the environment variable is unset.
func windowsProgramData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

// windowsAppData returns %AppData% (per-user roaming config), falling back to
// a best-effort path under the user's home directory if unset.
func windowsAppData() string {
	if v := os.Getenv("AppData"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "AppData", "Roaming")
}

// windowsLocalAppData returns %LocalAppData% (per-user local data), falling
// back to a best-effort path under the user's home directory if unset.
func windowsLocalAppData() string {
	if v := os.Getenv("LocalAppData"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "AppData", "Local")
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
