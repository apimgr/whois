package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apimgr/whois/src/client/config"
	"github.com/apimgr/whois/src/client/display"
	"github.com/apimgr/whois/src/client/lookup"
	"github.com/apimgr/whois/src/client/setup"
	"github.com/apimgr/whois/src/client/tui"
	"github.com/apimgr/whois/src/common/i18n"
	"github.com/apimgr/whois/src/update"
)

// Build info — set via -ldflags at build time
var (
	Version   = "dev"
	CommitID  = "unknown"
	BuildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run parses args and drives the CLI, returning an exit code.
func run(args []string) int {
	var (
		flagServer  string
		flagToken   string
		flagOutput  string
		flagFormat  string
		flagNoColor bool
		flagLang    string
		flagColor   string
		flagUpdate  string
		flagDebug   bool
		flagVersion bool
		flagStatus  bool
	)

	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&flagServer, "server", "", "Server base URL")
	fs.StringVar(&flagToken, "token", "", "API token")
	fs.StringVar(&flagOutput, "output", "", "Output format: json/text/raw (default: text)")
	fs.StringVar(&flagFormat, "format", "", "Output format alias for --output")
	fs.BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	fs.StringVar(&flagLang, "lang", "", "Language code (en, es, zh, fr, ar, de, ja)")
	fs.StringVar(&flagColor, "color", "", "Color output: always/never/auto (default: auto)")
	fs.StringVar(&flagUpdate, "update", "", "Update command: check/yes/branch=<name>")
	fs.BoolVar(&flagDebug, "debug", false, "Debug mode")
	fs.BoolVar(&flagVersion, "version", false, "Show version information")
	fs.BoolVar(&flagVersion, "v", false, "Show version information")
	fs.BoolVar(&flagStatus, "status", false, "Health check (exit 0=healthy, 1=unhealthy)")

	fs.Usage = func() {
		showHelp()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if flagVersion {
		showVersion()
		return 0
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		cfg = &config.CLIConfig{Format: "text"}
	}

	if flagServer != "" {
		cfg.Server = flagServer
	}
	if flagToken != "" {
		cfg.Token = flagToken
	}
	// --output takes precedence; --format is a legacy alias.
	if flagOutput != "" {
		cfg.Format = flagOutput
	} else if flagFormat != "" {
		cfg.Format = flagFormat
	}
	// --no-color overrides --color.
	if flagNoColor {
		flagColor = "never"
	}
	if flagDebug {
		cfg.Debug = true
	}

	applyEnvOverrides(cfg)

	// Resolve language: flag > config > env > default
	lang := flagLang
	if lang == "" {
		lang = cfg.Lang
	}
	if lang == "" {
		lang = os.Getenv("LANG")
		if len(lang) > 2 {
			lang = lang[:2]
		}
	}
	if !i18n.IsSupported(lang) {
		lang = "en"
	}
	tr, _ := i18n.Load(lang)
	_ = tr

	// Resolve color: flag > NO_COLOR env > auto-detect
	colorEnabled := resolveColor(flagColor)
	_ = colorEnabled

	// Handle --update before any server interaction
	if flagUpdate != "" {
		runUpdateCommand(flagUpdate, cfg)
		return 0
	}

	if flagStatus {
		runStatusCheck(cfg)
		return 0
	}

	remaining := fs.Args()

	if cfg.Server == "" {
		if display.Detect(false) == display.ModePlain {
			fmt.Fprintln(os.Stderr, "Error: no server configured. Set --server or run the client interactively to complete setup.")
			return 1
		}
		newCfg, wizErr := setup.Run(cfg)
		if wizErr != nil {
			fmt.Fprintf(os.Stderr, "Setup failed: %v\n", wizErr)
			return 1
		}
		cfg = newCfg
	}

	mode := display.Detect(len(remaining) > 0)

	switch mode {
	case display.ModeTUI:
		client := lookup.New(cfg.Server, cfg.Token, Version)
		if err := tui.Run(client); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			return 1
		}

	default:
		if len(remaining) == 0 {
			showHelp()
			return 0
		}
		runCLICommand(remaining, cfg)
	}
	return 0
}

// resolveColor returns true if ANSI color output should be used.
// Priority: --color flag > NO_COLOR env > TTY auto-detect.
func resolveColor(flagColor string) bool {
	switch strings.ToLower(flagColor) {
	case "always", "on", "yes", "1":
		return true
	case "never", "off", "no", "0":
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// runUpdateCommand handles --update check/yes/branch=<name>
func runUpdateCommand(cmd string, cfg *config.CLIConfig) {
	channel := update.ChannelStable
	if cfg.UpdateChannel != "" {
		channel = update.UpdateChannel(cfg.UpdateChannel)
	}

	switch {
	case cmd == "check":
		info, err := update.CheckForUpdates(Version, channel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking for updates: %v\n", err)
			os.Exit(1)
		}
		if info.Available {
			fmt.Printf("Update available: %s → %s\n", info.CurrentVersion, info.LatestVersion)
			fmt.Printf("Run '%s --update yes' to install.\n", filepath.Base(os.Args[0]))
		} else {
			fmt.Printf("Already up to date (%s)\n", info.CurrentVersion)
		}

	case cmd == "yes":
		fmt.Printf("Checking for updates (channel: %s)…\n", channel)
		if err := update.PerformUpdate(Version, channel); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Update complete.")

	case strings.HasPrefix(cmd, "branch="):
		branch := strings.TrimPrefix(cmd, "branch=")
		if branch == "" {
			fmt.Fprintln(os.Stderr, "Error: branch name required (e.g. --update branch=beta)")
			os.Exit(1)
		}
		cfg.UpdateChannel = branch
		if err := config.Save(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Update channel set to %q\n", branch)

	default:
		fmt.Fprintf(os.Stderr, "Unknown update command %q. Use: check, yes, branch=<name>\n", cmd)
		os.Exit(1)
	}
}

// applyEnvOverrides applies CASWHOIS_* environment variables as lowest-priority defaults
func applyEnvOverrides(cfg *config.CLIConfig) {
	if cfg.Server == "" {
		if v := os.Getenv("CASWHOIS_SERVER"); v != "" {
			cfg.Server = v
		}
	}
	if cfg.Token == "" {
		if v := os.Getenv("CASWHOIS_TOKEN"); v != "" {
			cfg.Token = v
		}
	}
	if cfg.Format == "" {
		if v := os.Getenv("CASWHOIS_FORMAT"); v != "" {
			cfg.Format = v
		}
	}
}

// runStatusCheck calls /server/healthz and exits 0 on success, 1 on failure
func runStatusCheck(cfg *config.CLIConfig) {
	if cfg.Server == "" {
		fmt.Fprintln(os.Stderr, "Error: no server configured")
		os.Exit(1)
	}
	client := lookup.New(cfg.Server, cfg.Token, Version)
	if err := client.HealthCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("healthy")
}

// runCLICommand dispatches a CLI command from non-flag arguments
func runCLICommand(args []string, cfg *config.CLIConfig) {
	client := lookup.New(cfg.Server, cfg.Token, Version)

	command := args[0]
	rest := args[1:]

	switch command {
	case "domain":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: domain required")
			os.Exit(1)
		}
		result, err := client.Domain(rest[0])
		printResult(result, err, cfg.Format)

	case "ip":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: IP address required")
			os.Exit(1)
		}
		result, err := client.IP(rest[0])
		printResult(result, err, cfg.Format)

	case "asn":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: ASN required")
			os.Exit(1)
		}
		result, err := client.ASN(rest[0])
		printResult(result, err, cfg.Format)

	case "validate":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: query required")
			os.Exit(1)
		}
		msg, err := client.Validate(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(msg)

	case "lookup":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: query required")
			os.Exit(1)
		}
		result, err := client.Lookup(rest[0])
		printResult(result, err, cfg.Format)

	default:
		result, err := client.Lookup(command)
		printResult(result, err, cfg.Format)
	}
}

// printResult outputs a lookup result in the requested format
func printResult(result *lookup.Result, err error, format string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(format) {
	case "json":
		data, jsonErr := json.MarshalIndent(result, "", "  ")
		if jsonErr != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %v\n", jsonErr)
			os.Exit(1)
		}
		fmt.Println(string(data))

	case "raw":
		fmt.Println(result.Raw)

	default:
		fmt.Printf("Query:     %s\n", result.Query)
		fmt.Printf("Type:      %s\n", result.Type)
		fmt.Printf("Server:    %s\n", result.Server)
		fmt.Printf("Timestamp: %s\n\n", result.Timestamp)
		fmt.Println(result.Raw)
	}
}

func showVersion() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Printf("%s version %s\n", binaryName, Version)
	fmt.Printf("Commit: %s\n", CommitID)
	fmt.Printf("Built: %s\n", BuildDate)
}

func showHelp() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Printf("%s - WHOIS lookup client\n\n", binaryName)
	fmt.Printf("Usage:\n  %s [flags] [command] [query]\n\n", binaryName)
	fmt.Println("Commands:")
	fmt.Println("  domain <domain>    Domain WHOIS lookup")
	fmt.Println("  ip <ip>            IP WHOIS lookup")
	fmt.Println("  asn <asn>          ASN WHOIS lookup")
	fmt.Println("  lookup <query>     Auto-detect query type")
	fmt.Println("  validate <query>   Validate query without lookup")
	fmt.Println("  <query>            Direct lookup (auto-detect)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -h, --help                   Show this help")
	fmt.Println("  -v, --version                Show version information")
	fmt.Println("  --status                     Health check (exit 0=healthy, 1=unhealthy)")
	fmt.Println("  --server URL                 Server base URL")
	fmt.Println("  --token TOKEN                API token")
	fmt.Println("  --output FORMAT              Output format: json/text/raw (default: text)")
	fmt.Println("  --format FORMAT              Alias for --output (legacy)")
	fmt.Println("  --lang CODE                  Language: en/es/zh/fr/ar/de/ja (default: en)")
	fmt.Println("  --color always|never|auto    Color output (default: auto)")
	fmt.Println("  --update check               Check for available updates")
	fmt.Println("  --update yes                 Download and install the latest update")
	fmt.Println("  --update branch=NAME         Switch update channel (stable/beta/daily)")
	fmt.Println("  --debug                      Debug mode")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  CASWHOIS_SERVER    Default server URL")
	fmt.Println("  CASWHOIS_TOKEN     API token")
	fmt.Println("  CASWHOIS_FORMAT    Default output format")
	fmt.Println("  NO_COLOR           Disable color output")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Printf("  %s\n", config.ConfigPath())
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s example.com\n", binaryName)
	fmt.Printf("  %s domain github.com --server http://localhost:64580\n", binaryName)
	fmt.Printf("  %s ip 8.8.8.8 --format json\n", binaryName)
	fmt.Printf("  %s asn AS15169\n", binaryName)
	fmt.Printf("  %s --update check\n", binaryName)
}
