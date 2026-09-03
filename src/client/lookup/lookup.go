package lookup

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result holds a parsed WHOIS lookup response
type Result struct {
	Query     string
	Type      string
	Server    string
	Timestamp string
	Raw       string
}

// apiResponse mirrors the server's unified response envelope
type apiResponse struct {
	Ok      bool            `json:"ok"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
	Message string          `json:"message,omitempty"`
}

// whoisData mirrors the data field of a WHOIS response
type whoisData struct {
	Query     string `json:"query"`
	Type      string `json:"type"`
	Server    string `json:"server"`
	Timestamp string `json:"timestamp"`
	Raw       string `json:"raw"`
}

// Client performs WHOIS lookups against a caswhois server
type Client struct {
	ServerURL string
	Token     string
	Version   string
	http      *http.Client
}

// New returns a Client configured for the given server URL and token
func New(serverURL, token, version string) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		Token:     token,
		Version:   version,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Lookup performs an auto-detect WHOIS query
func (c *Client) Lookup(query string) (*Result, error) {
	endpoint := fmt.Sprintf("%s/api/v1/whois/%s", c.ServerURL, url.PathEscape(query))
	return c.do(endpoint)
}

// Domain performs a domain-specific WHOIS query
func (c *Client) Domain(domain string) (*Result, error) {
	endpoint := fmt.Sprintf("%s/api/v1/whois/domain/%s", c.ServerURL, url.PathEscape(domain))
	return c.do(endpoint)
}

// IP performs an IP-specific WHOIS query
func (c *Client) IP(ip string) (*Result, error) {
	endpoint := fmt.Sprintf("%s/api/v1/whois/ip/%s", c.ServerURL, url.PathEscape(ip))
	return c.do(endpoint)
}

// ASN performs an ASN-specific WHOIS query
func (c *Client) ASN(asn string) (*Result, error) {
	endpoint := fmt.Sprintf("%s/api/v1/whois/asn/%s", c.ServerURL, url.PathEscape(asn))
	return c.do(endpoint)
}

// Validate checks whether a query is valid without performing a lookup
func (c *Client) Validate(query string) (string, error) {
	endpoint := fmt.Sprintf("%s/api/v1/whois/validate/%s", c.ServerURL, url.PathEscape(query))
	req, err := c.newRequest("GET", endpoint)
	if err != nil {
		return "", err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return string(body), nil
	}
	if !ar.Ok {
		return "", fmt.Errorf("%s: %s", ar.Error, ar.Message)
	}
	return ar.Message, nil
}

// HealthCheck calls /server/healthz and returns nil on success
func (c *Client) HealthCheck() error {
	endpoint := fmt.Sprintf("%s/server/healthz", c.ServerURL)
	req, err := c.newRequest("GET", endpoint)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// do executes an HTTP GET against endpoint and returns a parsed Result
func (c *Client) do(endpoint string) (*Result, error) {
	req, err := c.newRequest("GET", endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var ar apiResponse
		if jsonErr := json.Unmarshal(body, &ar); jsonErr == nil && ar.Message != "" {
			return nil, fmt.Errorf("%s: %s", ar.Error, ar.Message)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, err
	}
	if !ar.Ok {
		return nil, fmt.Errorf("%s: %s", ar.Error, ar.Message)
	}

	var wd whoisData
	if err := json.Unmarshal(ar.Data, &wd); err != nil {
		return nil, err
	}

	return &Result{
		Query:     wd.Query,
		Type:      wd.Type,
		Server:    wd.Server,
		Timestamp: wd.Timestamp,
		Raw:       wd.Raw,
	}, nil
}

// newRequest creates an HTTP request with standard headers
func (c *Client) newRequest(method, endpoint string) (*http.Request, error) {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return nil, err
	}

	userAgent := "caswhois-cli"
	if c.Version != "" {
		userAgent = fmt.Sprintf("caswhois-cli/%s", c.Version)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	if c.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	}

	return req, nil
}
