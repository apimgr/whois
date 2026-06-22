// Package reverse implements external reverse-WHOIS provider clients.
// It is optional — only consulted when a provider and API key are configured in server.yml.
// Supported providers: securitytrails, viewdns.
package reverse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient is the shared HTTP client used for all provider requests.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// Result is a single domain returned by an external reverse-WHOIS provider.
type Result struct {
	Domain   string `json:"domain"`
	Provider string `json:"provider"`
}

// SearchByOwner queries the configured external provider for domains matching owner.
// Returns an empty slice (not an error) when the provider is empty or unconfigured.
func SearchByOwner(ctx context.Context, provider, apiKey, owner string, maxResults int) ([]Result, error) {
	if maxResults <= 0 {
		maxResults = 100
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "securitytrails":
		return searchSecurityTrails(ctx, apiKey, owner, maxResults)
	case "whoxy":
		return searchWhoxy(ctx, apiKey, owner, maxResults)
	case "viewdns":
		return searchViewDNS(ctx, apiKey, owner, maxResults)
	case "", "none":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown reverse WHOIS provider %q — supported: securitytrails, whoxy, viewdns", provider)
	}
}

// searchSecurityTrails queries the SecurityTrails domain-search API.
// Doc: https://docs.securitytrails.com/reference/domain-search
func searchSecurityTrails(ctx context.Context, apiKey, owner string, maxResults int) ([]Result, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("securitytrails: api_key is required")
	}

	// POST /v1/domains/list with a whois_email or organization filter.
	// We try registrant_organization first; if that yields nothing, fall back to registrant_email.
	type filterValue struct {
		Value string `json:"value"`
	}
	type filter struct {
		RegistrantOrg   *filterValue `json:"registrant_organization,omitempty"`
		RegistrantEmail *filterValue `json:"registrant_email,omitempty"`
	}
	type payload struct {
		Filter filter `json:"filter"`
	}

	// Detect whether owner looks like an email address.
	var body payload
	if strings.Contains(owner, "@") {
		body.Filter.RegistrantEmail = &filterValue{Value: owner}
	} else {
		body.Filter.RegistrantOrg = &filterValue{Value: owner}
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.securitytrails.com/v1/domains/list",
		strings.NewReader(string(bodyBytes)),
	)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("APIKEY", apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("securitytrails: invalid API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails: unexpected status %d", resp.StatusCode)
	}

	var parsed struct {
		Records []struct {
			Hostname string `json:"hostname"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("securitytrails: decode response: %w", err)
	}

	results := make([]Result, 0, len(parsed.Records))
	for i, r := range parsed.Records {
		if i >= maxResults {
			break
		}
		if r.Hostname != "" {
			results = append(results, Result{Domain: r.Hostname, Provider: "securitytrails"})
		}
	}
	return results, nil
}

// searchWhoxy queries the Whoxy reverse-WHOIS API.
// Doc: https://www.whoxy.com/reverse-whois/
func searchWhoxy(ctx context.Context, apiKey, owner string, maxResults int) ([]Result, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("whoxy: api_key is required")
	}

	// Detect whether owner looks like an email to pick the correct filter key.
	filterKey := "company"
	if strings.Contains(owner, "@") {
		filterKey = "email"
	}

	endpoint := fmt.Sprintf(
		"https://api.whoxy.com/?key=%s&reverse=whois&%s=%s&mode=micro&page=1",
		url.QueryEscape(apiKey),
		filterKey,
		url.QueryEscape(owner),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("whoxy: build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("whoxy: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("whoxy: unexpected status %d", resp.StatusCode)
	}

	var parsed struct {
		StatusCode int `json:"status_code"`
		Domains    []struct {
			DomainName string `json:"domain_name"`
		} `json:"search_result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("whoxy: decode response: %w", err)
	}

	results := make([]Result, 0, len(parsed.Domains))
	for i, d := range parsed.Domains {
		if i >= maxResults {
			break
		}
		if d.DomainName != "" {
			results = append(results, Result{Domain: d.DomainName, Provider: "whoxy"})
		}
	}
	return results, nil
}

// searchViewDNS queries the ViewDNS reverse-WHOIS API.
// Doc: https://viewdns.info/api/docs/#reverse-whois-lookup
func searchViewDNS(ctx context.Context, apiKey, owner string, maxResults int) ([]Result, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("viewdns: api_key is required")
	}

	endpoint := fmt.Sprintf(
		"https://api.viewdns.info/reversewhois/?q=%s&apikey=%s&output=json",
		url.QueryEscape(owner),
		url.QueryEscape(apiKey),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("viewdns: build request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("viewdns: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("viewdns: unexpected status %d", resp.StatusCode)
	}

	var parsed struct {
		Response struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("viewdns: decode response: %w", err)
	}

	results := make([]Result, 0, len(parsed.Response.Domains))
	for i, d := range parsed.Response.Domains {
		if i >= maxResults {
			break
		}
		if d.Name != "" {
			results = append(results, Result{Domain: d.Name, Provider: "viewdns"})
		}
	}
	return results, nil
}
