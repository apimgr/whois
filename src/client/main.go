package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Build info - set via -ldflags at build time
var (
	Version      = "dev"
	CommitID     = "unknown"
	BuildDate    = "unknown"
	OfficialSite = "" // Empty = users must use --server flag
)

// WHOISResponse represents the API response structure
type WHOISResponse struct {
	Success bool   `json:"success"`
	Data    *WHOISData `json:"data,omitempty"`
	Error   *APIError  `json:"error,omitempty"`
}

// WHOISData contains the WHOIS lookup result
type WHOISData struct {
	Query     string `json:"query"`
	Type      string `json:"type"`
	Server    string `json:"server"`
	Timestamp string `json:"timestamp"`
	Raw       string `json:"raw"`
}

// APIError contains error details
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ClientConfig stores client configuration
type ClientConfig struct {
	Server string `json:"server"`
	Format string `json:"format"`
	Token  string `json:"token,omitempty"`
}

func main() {
	// Parse command line arguments
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "--version", "-v", "version":
		showVersion()
	case "--help", "-h", "help":
		showHelp()
	case "domain", "ip", "asn", "lookup":
		handleLookup(command, os.Args[2:])
	default:
		// Assume direct query
		handleDirectQuery(os.Args[1:])
	}
}

func showVersion() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Printf("%s version %s\n", binaryName, Version)
	fmt.Printf("Commit: %s\n", CommitID)
	fmt.Printf("Built: %s\n", BuildDate)
	if OfficialSite != "" {
		fmt.Printf("Default Server: %s\n", OfficialSite)
	}
}

func showHelp() {
	binaryName := filepath.Base(os.Args[0])
	fmt.Printf("%s - WHOIS lookup client (CLI mode)\n\n", binaryName)
	fmt.Println("Usage:")
	fmt.Printf("  %s [command] <query> [flags]\n\n", binaryName)
	fmt.Println("Commands:")
	fmt.Println("  domain <domain>    Lookup domain WHOIS (e.g., example.com)")
	fmt.Println("  ip <ip>            Lookup IP WHOIS (e.g., 8.8.8.8)")
	fmt.Println("  asn <asn>          Lookup ASN information (e.g., AS15169)")
	fmt.Println("  lookup <query>     Auto-detect query type")
	fmt.Println("  <query>            Direct lookup (auto-detect)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -h, --help         Show this help message")
	fmt.Println("  -v, --version      Show version information")
	fmt.Println("  --server <url>     Server URL (required if not configured)")
	fmt.Println("  --format <fmt>     Output format: json, xml, text, raw (default: text)")
	fmt.Println("  --token <token>    API token for authentication (optional)")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  CASWHOIS_SERVER    Default server URL")
	fmt.Println("  CASWHOIS_TOKEN     API token")
	fmt.Println("  CASWHOIS_FORMAT    Default output format")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s example.com\n", binaryName)
	fmt.Printf("  %s domain github.com --server http://localhost:64580\n", binaryName)
	fmt.Printf("  %s ip 8.8.8.8 --format json\n", binaryName)
	fmt.Printf("  %s asn AS15169\n", binaryName)
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  Set CASWHOIS_SERVER environment variable to avoid --server flag:")
	fmt.Println("  export CASWHOIS_SERVER=http://localhost:64580")
}

func handleLookup(command string, args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: query required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s %s <query> [flags]\n", filepath.Base(os.Args[0]), command)
		os.Exit(1)
	}

	query := args[0]
	flags := parseFlags(args[1:])

	// Validate server URL
	serverURL := getServerURL(flags)
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Error: server URL required")
		fmt.Fprintln(os.Stderr, "Set CASWHOIS_SERVER environment variable or use --server flag")
		os.Exit(1)
	}

	// Determine endpoint based on command
	var endpoint string
	if command == "lookup" || command == os.Args[1] {
		// Auto-detect
		endpoint = fmt.Sprintf("%s/api/v1/whois/%s", strings.TrimRight(serverURL, "/"), url.PathEscape(query))
	} else {
		// Specific type
		endpoint = fmt.Sprintf("%s/api/v1/whois/%s/%s", strings.TrimRight(serverURL, "/"), command, url.PathEscape(query))
	}

	// Perform lookup
	performLookup(endpoint, flags)
}

func handleDirectQuery(args []string) {
	if len(args) == 0 {
		showHelp()
		os.Exit(0)
	}

	query := args[0]
	flags := parseFlags(args[1:])

	serverURL := getServerURL(flags)
	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Error: server URL required")
		fmt.Fprintln(os.Stderr, "Set CASWHOIS_SERVER environment variable or use --server flag")
		os.Exit(1)
	}

	endpoint := fmt.Sprintf("%s/api/v1/whois/%s", strings.TrimRight(serverURL, "/"), url.PathEscape(query))
	performLookup(endpoint, flags)
}

func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		}
	}
	return flags
}

func getServerURL(flags map[string]string) string {
	// Priority: flag > env > OfficialSite
	if url, ok := flags["server"]; ok {
		return url
	}
	if url := os.Getenv("CASWHOIS_SERVER"); url != "" {
		return url
	}
	return OfficialSite
}

func getFormat(flags map[string]string) string {
	// Priority: flag > env > default
	if format, ok := flags["format"]; ok {
		return format
	}
	if format := os.Getenv("CASWHOIS_FORMAT"); format != "" {
		return format
	}
	return "text"
}

func performLookup(endpoint string, flags map[string]string) {
	format := getFormat(flags)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", fmt.Sprintf("caswhois-cli/%s", Version))

	// Set authentication token if provided
	if token, ok := flags["token"]; ok {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	} else if token := os.Getenv("CASWHOIS_TOKEN"); token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	// Set Accept header based on format
	switch format {
	case "json":
		req.Header.Set("Accept", "application/json")
	case "xml":
		req.Header.Set("Accept", "application/xml")
	case "text":
		req.Header.Set("Accept", "text/plain")
	case "raw":
		// Raw format returns just the WHOIS text
		req.Header.Set("Accept", "text/plain")
	default:
		req.Header.Set("Accept", "application/json")
	}

	// Perform request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error performing lookup: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	// Handle response based on status code and format
	if resp.StatusCode != http.StatusOK {
		// Try to parse as JSON error
		var apiResp WHOISResponse
		if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Error != nil {
			fmt.Fprintf(os.Stderr, "Error: %s (%s)\n", apiResp.Error.Message, apiResp.Error.Code)
		} else {
			fmt.Fprintf(os.Stderr, "Error: HTTP %d\n%s\n", resp.StatusCode, string(body))
		}
		os.Exit(1)
	}

	// Output response based on format
	switch format {
	case "json":
		// Pretty-print JSON
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err == nil {
			prettyJSON, _ := json.MarshalIndent(jsonData, "", "  ")
			fmt.Println(string(prettyJSON))
		} else {
			fmt.Println(string(body))
		}
	case "xml":
		// Pretty-print XML
		var xmlData interface{}
		if err := xml.Unmarshal(body, &xmlData); err == nil {
			prettyXML, _ := xml.MarshalIndent(xmlData, "", "  ")
			fmt.Println(string(prettyXML))
		} else {
			fmt.Println(string(body))
		}
	case "text":
		// Parse JSON and extract raw WHOIS data
		var apiResp WHOISResponse
		if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Success && apiResp.Data != nil {
			// Print metadata
			fmt.Printf("Query:     %s\n", apiResp.Data.Query)
			fmt.Printf("Type:      %s\n", apiResp.Data.Type)
			fmt.Printf("Server:    %s\n", apiResp.Data.Server)
			fmt.Printf("Timestamp: %s\n\n", apiResp.Data.Timestamp)
			// Print raw WHOIS data
			fmt.Println(apiResp.Data.Raw)
		} else {
			// Fallback to plain body
			fmt.Println(string(body))
		}
	case "raw":
		// Just the raw WHOIS output, no metadata
		var apiResp WHOISResponse
		if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Success && apiResp.Data != nil {
			fmt.Println(apiResp.Data.Raw)
		} else {
			fmt.Println(string(body))
		}
	default:
		fmt.Println(string(body))
	}
}

