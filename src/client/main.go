package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	Version      = "dev"
	CommitID     = "unknown"
	BuildDate    = "unknown"
	OfficialSite = ""
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run parses args and drives the CLI, returning an exit code.
func run(args []string) int {
	var (
		flagHelp      bool
		flagServer    string
		flagToken     string
		flagTokenFile string
		flagOutput    string
		flagFormat    string
		flagNoColor   bool
		flagLang      string
		flagColor     string
		flagUpdate    string
		flagDebug     bool
		flagVersion   bool
		flagStatus    bool
		flagConfig    string
	)

	// --shell is handled before flag parsing since it takes positional
	// arguments (completions|init|help [SHELL]) rather than a single value
	// (AI.md PART 32: "Shell Completions").
	if len(args) > 0 && args[0] == "--shell" {
		return handleShellCommand(args[1:])
	}

	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.BoolVar(&flagHelp, "help", false, "Show help message")
	fs.BoolVar(&flagHelp, "h", false, "Show help message")
	fs.StringVar(&flagServer, "server", "", "Server base URL")
	fs.StringVar(&flagToken, "token", "", "API token")
	fs.StringVar(&flagTokenFile, "token-file", "", "Read API token from file")
	fs.StringVar(&flagOutput, "output", "", "Output format: json/table/plain (default: table)")
	fs.StringVar(&flagFormat, "format", "", "Output format alias for --output")
	fs.BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	fs.StringVar(&flagLang, "lang", "", "Language code (en, es, zh, fr, ar, de, ja)")
	fs.StringVar(&flagColor, "color", "auto", "Color output: always/never/auto (default: auto)")
	fs.StringVar(&flagUpdate, "update", "", "Update command: check/yes/branch=<name>")
	fs.BoolVar(&flagDebug, "debug", false, "Debug mode")
	fs.BoolVar(&flagVersion, "version", false, "Show version information")
	fs.BoolVar(&flagVersion, "v", false, "Show version information")
	fs.BoolVar(&flagStatus, "status", false, "Health check (exit 0=healthy, 1=unhealthy)")
	fs.StringVar(&flagConfig, "config", "", "Config file to use (name, name.yml, or absolute path)")

	fs.Usage = func() {
		showHelp()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if flagHelp {
		showHelp()
		return 0
	}

	if flagVersion {
		showVersion()
		return 0
	}

	configPath := config.ResolveConfigPath(flagConfig)
	cfg, err := config.LoadFrom(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		cfg = &config.CLIConfig{Format: "table"}
	}

	if flagServer != "" {
		cfg.Server = flagServer
	}
	if flagToken != "" {
		cfg.Token = flagToken
	}
	if flagToken == "" && flagTokenFile != "" {
		data, readErr := os.ReadFile(flagTokenFile)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading --token-file: %v\n", readErr)
			return 1
		}
		cfg.Token = strings.TrimSpace(string(data))
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
		return runUpdateCommand(flagUpdate, cfg, configPath)
	}

	if flagStatus {
		return runStatusCheck(cfg)
	}

	remaining := fs.Args()

	if cfg.Server == "" {
		if display.Detect(false) == display.ModePlain {
			fmt.Fprintln(os.Stderr, "Error: no server configured. Set --server or run the client interactively to complete setup.")
			return 1
		}
		newCfg, wizErr := setup.RunTo(cfg, configPath)
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
		return runCLICommand(remaining, cfg)
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

// runUpdateCommand handles --update check/yes/branch=<name> and returns an exit code.
// Per AI.md PART 32: CLI uses server's /api/autodiscover for update info.
func runUpdateCommand(cmd string, cfg *config.CLIConfig, configPath string) int {
	// Per AI.md PART 22: --update without argument defaults to "yes"
	if cmd == "" {
		cmd = "yes"
	}

	switch {
	case cmd == "check":
		// Use autodiscover if server is configured; fall back to GitHub otherwise
		if cfg.Server != "" {
			info, err := update.CheckCLIUpdates(cfg.Server, Version)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking for updates via server: %v\n", err)
				return 1
			}
			if info.Available {
				fmt.Printf("Update available: %s → %s\n", info.CurrentVersion, info.LatestVersion)
				fmt.Printf("Run '%s --update yes' to install.\n", filepath.Base(os.Args[0]))
			} else {
				fmt.Printf("Already up to date (%s)\n", info.CurrentVersion)
			}
		} else {
			channel := update.ChannelStable
			if cfg.UpdateChannel != "" {
				channel = update.UpdateChannel(cfg.UpdateChannel)
			}
			info, err := update.CheckForUpdates(Version, channel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error checking for updates: %v\n", err)
				return 1
			}
			if info.Available {
				fmt.Printf("Update available: %s → %s\n", info.CurrentVersion, info.LatestVersion)
				fmt.Printf("Run '%s --update yes' to install.\n", filepath.Base(os.Args[0]))
			} else {
				fmt.Printf("Already up to date (%s)\n", info.CurrentVersion)
			}
		}

	case cmd == "yes":
		// Use autodiscover if server is configured; fall back to GitHub otherwise
		if cfg.Server != "" {
			fmt.Println("Checking for updates via server…")
			if err := update.PerformCLIUpdate(cfg.Server, Version); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				return 1
			}
			fmt.Println("Update complete.")
		} else {
			channel := update.ChannelStable
			if cfg.UpdateChannel != "" {
				channel = update.UpdateChannel(cfg.UpdateChannel)
			}
			fmt.Printf("Checking for updates (channel: %s)…\n", channel)
			if err := update.PerformUpdate(Version, channel); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				return 1
			}
			fmt.Println("Update complete.")
		}

	case strings.HasPrefix(cmd, "branch="):
		branch := strings.TrimPrefix(cmd, "branch=")
		if branch == "" {
			fmt.Fprintln(os.Stderr, "Error: branch name required (e.g. --update branch=beta)")
			return 1
		}
		cfg.UpdateChannel = branch
		if err := config.SaveTo(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return 1
		}
		fmt.Printf("Update channel set to %q\n", branch)

	default:
		fmt.Fprintf(os.Stderr, "Unknown update command %q. Use: check, yes, branch=<name>\n", cmd)
		return 1
	}
	return 0
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

// runStatusCheck calls /server/healthz and returns 0 on success, 1 on failure.
func runStatusCheck(cfg *config.CLIConfig) int {
	if cfg.Server == "" {
		fmt.Fprintln(os.Stderr, "Error: no server configured")
		return 1
	}
	client := lookup.New(cfg.Server, cfg.Token, Version)
	if err := client.HealthCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "unhealthy: %v\n", err)
		return 1
	}
	fmt.Println("healthy")
	return 0
}

// runCLICommand dispatches a CLI command from non-flag arguments and returns an exit code.
func runCLICommand(args []string, cfg *config.CLIConfig) int {
	client := lookup.New(cfg.Server, cfg.Token, Version)

	command := args[0]
	rest := args[1:]

	switch command {
	case "domain":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: domain required")
			return 1
		}
		result, err := client.Domain(rest[0])
		return printResult(result, err, cfg.Format)

	case "ip":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: IP address required")
			return 1
		}
		result, err := client.IP(rest[0])
		return printResult(result, err, cfg.Format)

	case "asn":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: ASN required")
			return 1
		}
		result, err := client.ASN(rest[0])
		return printResult(result, err, cfg.Format)

	case "validate":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: query required")
			return 1
		}
		msg, err := client.Validate(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid: %v\n", err)
			return 1
		}
		fmt.Println(msg)
		return 0

	case "lookup":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "Error: query required")
			return 1
		}
		result, err := client.Lookup(rest[0])
		return printResult(result, err, cfg.Format)

	default:
		result, err := client.Lookup(command)
		return printResult(result, err, cfg.Format)
	}
}

// printResult outputs a lookup result in the requested format and returns an exit code.
func printResult(result *lookup.Result, err error, format string) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	switch strings.ToLower(format) {
	case "json":
		data, jsonErr := json.MarshalIndent(result, "", "  ")
		if jsonErr != nil {
			fmt.Fprintf(os.Stderr, "Error marshalling JSON: %v\n", jsonErr)
			return 1
		}
		fmt.Println(string(data))

	case "plain":
		fmt.Println(result.Raw)

	default:
		fmt.Printf("Query:     %s\n", result.Query)
		fmt.Printf("Type:      %s\n", result.Type)
		fmt.Printf("Server:    %s\n", result.Server)
		fmt.Printf("Timestamp: %s\n\n", result.Timestamp)
		fmt.Println(result.Raw)
	}
	return 0
}

func showVersion() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Printf("%s version %s (%s) built on %s for %s/%s\n",
		binaryName, Version, CommitID, BuildDate, runtime.GOOS, runtime.GOARCH)
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
	fmt.Println("  --token-file FILE            Read API token from file")
	fmt.Println("  --output FORMAT              Output format: json/table/plain (default: table)")
	fmt.Println("  --format FORMAT              Alias for --output (legacy)")
	fmt.Println("  --lang CODE                  Language: en/es/zh/fr/ar/de/ja (default: en)")
	fmt.Println("  --color always|never|auto    Color output (default: auto)")
	fmt.Println("  --update check               Check for available updates")
	fmt.Println("  --update yes                 Download and install the latest update")
	fmt.Println("  --update branch=NAME         Switch update channel (stable/beta/daily)")
	fmt.Println("  --config NAME                Config file to use (name, name.yml, or absolute path)")
	fmt.Println("  --debug                      Debug mode")
	fmt.Println("  --shell completions [SHELL]  Print shell completions (auto-detect if SHELL omitted)")
	fmt.Println("  --shell init [SHELL]         Print shell init command (auto-detect if SHELL omitted)")
	fmt.Println("  --shell help                 Show shell integration help")
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

// handleShellCommand implements --shell completions|init|help [SHELL] and
// returns an exit code (AI.md PART 32: "Shell Completions (Built-in, NON-NEGOTIABLE)").
func handleShellCommand(args []string) int {
	binaryName := filepath.Base(os.Args[0])

	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: --shell [completions|init|help] [SHELL]")
		return 1
	}

	cmd := args[0]
	shell := ""
	if len(args) > 1 {
		shell = args[1]
	} else {
		shell = detectShell()
	}

	switch cmd {
	case "completions":
		return printCompletions(shell, binaryName)
	case "init":
		return printInit(shell, binaryName)
	case "help":
		fmt.Printf("Shell integration for %s:\n", binaryName)
		fmt.Println("  --shell completions [SHELL]  Print shell completions")
		fmt.Println("  --shell init [SHELL]         Print shell init command")
		fmt.Println("  SHELL: bash, zsh, fish, sh, dash, ksh, powershell, pwsh (auto-detect if omitted)")
		return 0
	default:
		fmt.Fprintln(os.Stderr, "Usage: --shell [completions|init|help] [SHELL]")
		return 1
	}
}

// detectShell extracts the shell name from the $SHELL environment variable,
// falling back to "bash" when unset.
func detectShell() string {
	shellPath := os.Getenv("SHELL")
	if shellPath == "" {
		return "bash"
	}
	return filepath.Base(shellPath)
}

// printCompletions prints a completion script for the given shell to stdout.
func printCompletions(shell, binaryName string) int {
	switch shell {
	case "bash":
		fmt.Print(generateBashCompletions(binaryName))
	case "zsh":
		fmt.Print(generateZshCompletions(binaryName))
	case "fish":
		fmt.Print(generateFishCompletions(binaryName))
	case "sh", "dash", "ksh":
		fmt.Print(generatePosixCompletions(binaryName))
	case "powershell", "pwsh":
		fmt.Print(generatePowershellCompletions(binaryName))
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported shell %q\n", shell)
		return 1
	}
	return 0
}

// printInit prints the eval-ready init command for the given shell.
func printInit(shell, binaryName string) int {
	switch shell {
	case "bash":
		fmt.Printf("source <(%s --shell completions bash)\n", binaryName)
	case "zsh":
		fmt.Printf("source <(%s --shell completions zsh)\n", binaryName)
	case "fish":
		fmt.Printf("%s --shell completions fish | source\n", binaryName)
	case "sh", "dash", "ksh":
		fmt.Printf("eval \"$(%s --shell completions %s)\"\n", binaryName, shell)
	case "powershell", "pwsh":
		fmt.Printf("Invoke-Expression (& %s --shell completions powershell)\n", binaryName)
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported shell %q\n", shell)
		return 1
	}
	return 0
}

// cliCommands lists the client's project-specific subcommands for completion generation.
var cliCommands = []string{"domain", "ip", "asn", "lookup", "validate"}

// cliFlags lists the client's long-form flags for completion generation.
var cliFlags = []string{
	"--help", "--version", "--status", "--server", "--token", "--token-file",
	"--output", "--format", "--lang", "--color", "--update", "--config",
	"--debug", "--no-color", "--shell",
}

// generateBashCompletions returns a bash completion script for binaryName.
func generateBashCompletions(binaryName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "_%s_completions() {\n", binaryName)
	fmt.Fprintf(&b, "    local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	fmt.Fprintf(&b, "    local opts=\"%s %s\"\n", strings.Join(cliCommands, " "), strings.Join(cliFlags, " "))
	fmt.Fprintf(&b, "    COMPREPLY=($(compgen -W \"${opts}\" -- \"${cur}\"))\n")
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "complete -F _%s_completions %s\n", binaryName, binaryName)
	return b.String()
}

// generateZshCompletions returns a zsh completion script for binaryName.
func generateZshCompletions(binaryName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#compdef %s\n\n", binaryName)
	fmt.Fprintf(&b, "_%s() {\n", binaryName)
	fmt.Fprintf(&b, "    local -a opts\n")
	fmt.Fprintf(&b, "    opts=(%s %s)\n", strings.Join(cliCommands, " "), strings.Join(cliFlags, " "))
	fmt.Fprintf(&b, "    _describe 'command' opts\n")
	fmt.Fprintf(&b, "}\n\n")
	fmt.Fprintf(&b, "compdef _%s %s\n", binaryName, binaryName)
	return b.String()
}

// generateFishCompletions returns a fish completion script for binaryName.
func generateFishCompletions(binaryName string) string {
	var b strings.Builder
	for _, c := range cliCommands {
		fmt.Fprintf(&b, "complete -c %s -n '__fish_use_subcommand' -a '%s'\n", binaryName, c)
	}
	for _, f := range cliFlags {
		fmt.Fprintf(&b, "complete -c %s -l '%s'\n", binaryName, strings.TrimPrefix(f, "--"))
	}
	return b.String()
}

// generatePosixCompletions returns a minimal POSIX-shell completion helper for binaryName.
func generatePosixCompletions(binaryName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# POSIX shell has no native completion API.\n")
	fmt.Fprintf(&b, "# Available commands and flags for %s:\n", binaryName)
	fmt.Fprintf(&b, "# %s %s\n", strings.Join(cliCommands, " "), strings.Join(cliFlags, " "))
	return b.String()
}

// generatePowershellCompletions returns a PowerShell completion script for binaryName.
func generatePowershellCompletions(binaryName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Register-ArgumentCompleter -Native -CommandName %s -ScriptBlock {\n", binaryName)
	fmt.Fprintf(&b, "    param($wordToComplete, $commandAst, $cursorPosition)\n")
	fmt.Fprintf(&b, "    $opts = @(%s, %s)\n",
		"'"+strings.Join(cliCommands, "', '")+"'",
		"'"+strings.Join(cliFlags, "', '")+"'")
	fmt.Fprintf(&b, "    $opts | Where-Object { $_ -like \"$wordToComplete*\" } | ForEach-Object {\n")
	fmt.Fprintf(&b, "        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)\n")
	fmt.Fprintf(&b, "    }\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}
