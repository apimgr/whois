package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/casapps/caswhois/src/client/config"
	"github.com/casapps/caswhois/src/client/display"
	"github.com/casapps/caswhois/src/client/lookup"
	"github.com/casapps/caswhois/src/client/setup"
	"github.com/casapps/caswhois/src/client/tui"
)

// Build info — set via -ldflags at build time
var (
	Version   = "dev"
	CommitID  = "unknown"
	BuildDate = "unknown"
)

func main() {
	var (
		flagServer  string
		flagToken   string
		flagFormat  string
		flagDebug   bool
		flagVersion bool
		flagStatus  bool
	)

	flag.StringVar(&flagServer, "server", "", "Server base URL")
	flag.StringVar(&flagToken, "token", "", "API token")
	flag.StringVar(&flagFormat, "format", "", "Output format: json/text/raw (default: text)")
	flag.BoolVar(&flagDebug, "debug", false, "Debug mode")
	flag.BoolVar(&flagVersion, "version", false, "Show version information")
	flag.BoolVar(&flagVersion, "v", false, "Show version information")
	flag.BoolVar(&flagStatus, "status", false, "Health check (exit 0=healthy, 1=unhealthy)")

	flag.Usage = func() {
		showHelp()
	}
	flag.Parse()

	if flagVersion {
		showVersion()
		return
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
	if flagFormat != "" {
		cfg.Format = flagFormat
	}
	if flagDebug {
		cfg.Debug = true
	}

	applyEnvOverrides(cfg)

	if flagStatus {
		runStatusCheck(cfg)
		return
	}

	args := flag.Args()

	if cfg.Server == "" {
		if display.Detect(false) == display.ModePlain {
			fmt.Fprintln(os.Stderr, "Error: no server configured. Set --server or run the client interactively to complete setup.")
			os.Exit(1)
		}
		newCfg, wizErr := setup.Run(cfg)
		if wizErr != nil {
			fmt.Fprintf(os.Stderr, "Setup failed: %v\n", wizErr)
			os.Exit(1)
		}
		cfg = newCfg
	}

	mode := display.Detect(len(args) > 0)

	switch mode {
	case display.ModeTUI:
		client := lookup.New(cfg.Server, cfg.Token, Version)
		if err := tui.Run(client); err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}

	default:
		if len(args) == 0 {
			showHelp()
			return
		}
		runCLICommand(args, cfg)
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

	noColor := os.Getenv("NO_COLOR") != ""
	_ = noColor

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
	fmt.Println("  -h, --help         Show this help")
	fmt.Println("  -v, --version      Show version information")
	fmt.Println("  --status           Health check (exit 0=healthy, 1=unhealthy)")
	fmt.Println("  --server URL       Server base URL")
	fmt.Println("  --token TOKEN      API token")
	fmt.Println("  --format FORMAT    Output format: json/text/raw (default: text)")
	fmt.Println("  --debug            Debug mode")
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
}
