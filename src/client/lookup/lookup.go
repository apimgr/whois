package lookup

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/whois/src/config"
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
	ServerURL      string
	Token          string
	Version        string
	http           *http.Client
	apiVersionOnce sync.Once
	apiVersion     string
	apiVersionErr  error
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
	apiBase, err := c.apiBasePath()
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s%s/whois/%s", c.ServerURL, apiBase, url.PathEscape(query))
	return c.do(endpoint)
}

// Domain performs a domain-specific WHOIS query
func (c *Client) Domain(domain string) (*Result, error) {
	apiBase, err := c.apiBasePath()
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s%s/whois/domain/%s", c.ServerURL, apiBase, url.PathEscape(domain))
	return c.do(endpoint)
}

// IP performs an IP-specific WHOIS query
func (c *Client) IP(ip string) (*Result, error) {
	apiBase, err := c.apiBasePath()
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s%s/whois/ip/%s", c.ServerURL, apiBase, url.PathEscape(ip))
	return c.do(endpoint)
}

// ASN performs an ASN-specific WHOIS query
func (c *Client) ASN(asn string) (*Result, error) {
	apiBase, err := c.apiBasePath()
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s%s/whois/asn/%s", c.ServerURL, apiBase, url.PathEscape(asn))
	return c.do(endpoint)
}

// Validate checks whether a query is valid without performing a lookup
func (c *Client) Validate(query string) (string, error) {
	apiBase, err := c.apiBasePath()
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s%s/whois/validate/%s", c.ServerURL, apiBase, url.PathEscape(query))
	req, err := c.newRequest("GET", endpoint)
	if err != nil {
		return "", err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

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

func (c *Client) apiBasePath() (string, error) {
	c.apiVersionOnce.Do(func() {
		request, err := http.NewRequest(http.MethodGet, c.ServerURL+"/api/autodiscover", nil)
		if err != nil {
			c.apiVersionErr = err
			return
		}
		response, err := c.http.Do(request)
		if err != nil {
			c.apiVersionErr = err
			return
		}
		defer func() { _ = response.Body.Close() }()
		var discovery struct {
			APIVersion string `json:"api_version"`
			Data       struct {
				APIVersion string `json:"api_version"`
			} `json:"data"`
		}
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&discovery) != nil {
			c.apiVersion = config.DefaultAPIVersion
			return
		}
		if discovery.APIVersion == "" {
			discovery.APIVersion = discovery.Data.APIVersion
		}
		if validAPIVersion(discovery.APIVersion) {
			c.apiVersion = discovery.APIVersion
		} else {
			c.apiVersion = config.DefaultAPIVersion
		}
	})
	if c.apiVersionErr != nil {
		return "", c.apiVersionErr
	}
	return (&config.ServerConfig{APIVersion: c.apiVersion}).APIBasePath(), nil
}

func validAPIVersion(version string) bool {
	if len(version) < 2 || version[0] != 'v' {
		return false
	}
	for _, char := range version[1:] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
