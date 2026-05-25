package server

import (
	"fmt"
	"net/http"
)

// handleAboutPage serves the about page
// GET /about
func (s *Server) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	html := renderAboutPageHTML(s.config.BrandingTitle, s.config.BrandingDescription)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleDocsPage serves the API documentation page
// GET /docs
func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	html := renderDocsPageHTML(s.config.BrandingTitle)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// renderAboutPageHTML generates the about page HTML
func renderAboutPageHTML(title, description string) string {
	if title == "" {
		title = "CASWHOIS"
	}
	if description == "" {
		description = "A fast, reliable WHOIS lookup service built with Go"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="About %s - WHOIS lookup service">
    <title>About - %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            min-height: 100vh;
            padding: 2rem 1rem;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        h1 {
            font-size: 2.5rem;
            color: #2d3748;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: #718096;
            font-size: 1.125rem;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        h2 {
            color: #2d3748;
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }
        
        p {
            color: #4a5568;
            line-height: 1.7;
            margin-bottom: 1rem;
        }
        
        ul {
            list-style: none;
            padding: 0;
        }
        
        li {
            color: #4a5568;
            padding: 0.5rem 0;
            padding-left: 1.5rem;
            position: relative;
        }
        
        li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #667eea;
            font-weight: bold;
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .feature {
            padding: 1.5rem;
            background: #f7fafc;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .feature h3 {
            color: #2d3748;
            font-size: 1.125rem;
            margin-bottom: 0.5rem;
        }
        
        .feature p {
            color: #718096;
            font-size: 0.95rem;
            margin: 0;
        }
        
        .nav-links {
            text-align: center;
            margin-top: 2rem;
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            margin: 0.5rem;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 2rem;
            }
            
            .card {
                padding: 1.5rem;
            }
            
            .feature-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>About %s</h1>
            <p class="subtitle">%s</p>
        </div>
        
        <div class="card">
            <h2>What is WHOIS?</h2>
            <p>
                WHOIS is a query and response protocol that is widely used for querying databases that store 
                registered users or assignees of an Internet resource, such as domain names, IP addresses, and 
                autonomous system numbers (ASNs).
            </p>
            <p>
                %s provides a fast, reliable interface to query WHOIS information from various registrars 
                and Regional Internet Registries (RIRs) worldwide.
            </p>
        </div>
        
        <div class="card">
            <h2>Features</h2>
            <div class="feature-grid">
                <div class="feature">
                    <h3>⚡ Fast Lookups</h3>
                    <p>Optimized caching and connection pooling for rapid responses</p>
                </div>
                <div class="feature">
                    <h3>🌍 Global Coverage</h3>
                    <p>Support for all major RIRs and domain registrars</p>
                </div>
                <div class="feature">
                    <h3>🔒 Secure</h3>
                    <p>Built with security best practices and rate limiting</p>
                </div>
                <div class="feature">
                    <h3>📊 Multiple Formats</h3>
                    <p>JSON, XML, plain text, and HTML output formats</p>
                </div>
                <div class="feature">
                    <h3>🔌 RESTful API</h3>
                    <p>Clean, well-documented API for programmatic access</p>
                </div>
                <div class="feature">
                    <h3>💾 Bulk Lookups</h3>
                    <p>Query multiple domains or IPs in a single request</p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Supported Query Types</h2>
            <ul>
                <li><strong>Domain Names</strong> - example.com, github.com, etc.</li>
                <li><strong>IPv4 Addresses</strong> - 8.8.8.8, 1.1.1.1, etc.</li>
                <li><strong>IPv6 Addresses</strong> - 2001:4860:4860::8888, etc.</li>
                <li><strong>ASN Numbers</strong> - AS15169, AS13335, etc.</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Technology Stack</h2>
            <p>
                %s is built with modern technologies for reliability and performance:
            </p>
            <ul>
                <li><strong>Go</strong> - Fast, compiled binary with no external dependencies</li>
                <li><strong>SQLite/PostgreSQL</strong> - Flexible database options</li>
                <li><strong>In-Memory Cache</strong> - Rapid response times</li>
                <li><strong>Docker</strong> - Easy deployment and portability</li>
            </ul>
        </div>
        
        <div class="nav-links">
            <a href="/" class="btn">← Back to Search</a>
            <a href="/docs" class="btn btn-secondary">API Documentation</a>
        </div>
    </div>
</body>
</html>`, title, title, title, description, title, title)
}

// renderDocsPageHTML generates the API documentation page HTML
func renderDocsPageHTML(title string) string {
	if title == "" {
		title = "CASWHOIS"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="%s API Documentation">
    <title>API Documentation - %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            min-height: 100vh;
            padding: 2rem 1rem;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        h1 {
            font-size: 2.5rem;
            color: #2d3748;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: #718096;
            font-size: 1.125rem;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        h2 {
            color: #2d3748;
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e2e8f0;
        }
        
        h3 {
            color: #4a5568;
            font-size: 1.125rem;
            margin-top: 1.5rem;
            margin-bottom: 0.75rem;
        }
        
        p {
            color: #4a5568;
            line-height: 1.7;
            margin-bottom: 1rem;
        }
        
        .endpoint {
            background: #f7fafc;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border-left: 4px solid #667eea;
        }
        
        .method {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
            margin-right: 0.75rem;
        }
        
        .method-get {
            background: #c6f6d5;
            color: #22543d;
        }
        
        .method-post {
            background: #bee3f8;
            color: #2c5282;
        }
        
        .endpoint-path {
            color: #2d3748;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 1rem;
        }
        
        .endpoint-desc {
            color: #718096;
            margin-top: 0.5rem;
        }
        
        code {
            background: #2d3748;
            color: #e2e8f0;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.875rem;
        }
        
        pre {
            background: #2d3748;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        pre code {
            background: none;
            padding: 0;
        }
        
        table {
            width: 100%%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        
        th, td {
            text-align: left;
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
        }
        
        th {
            background: #f7fafc;
            color: #2d3748;
            font-weight: 600;
        }
        
        .nav-links {
            text-align: center;
            margin-top: 2rem;
        }
        
        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            margin: 0.5rem;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 2rem;
            }
            
            .card {
                padding: 1.5rem;
            }
            
            .endpoint {
                padding: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Documentation</h1>
            <p class="subtitle">RESTful API for WHOIS lookups</p>
        </div>
        
        <div class="card">
            <h2>Base URL</h2>
            <pre><code>/api/v1</code></pre>
            <p>All API endpoints are versioned and prefixed with <code>/api/v1</code>.</p>
        </div>
        
        <div class="card">
            <h2>Authentication</h2>
            <p>
                Most endpoints are public and do not require authentication. 
                Bulk lookup endpoints require an API token for authentication.
            </p>
            <pre><code>Authorization: Bearer your_api_token_here</code></pre>
        </div>
        
        <div class="card">
            <h2>Response Formats</h2>
            <p>The API supports multiple response formats through content negotiation:</p>
            
            <table>
                <tr>
                    <th>Format</th>
                    <th>Accept Header</th>
                    <th>Query Parameter</th>
                </tr>
                <tr>
                    <td>JSON (default)</td>
                    <td><code>application/json</code></td>
                    <td><code>?format=json</code></td>
                </tr>
                <tr>
                    <td>XML</td>
                    <td><code>application/xml</code></td>
                    <td><code>?format=xml</code></td>
                </tr>
                <tr>
                    <td>Plain Text</td>
                    <td><code>text/plain</code></td>
                    <td><code>?format=text</code></td>
                </tr>
                <tr>
                    <td>HTML</td>
                    <td><code>text/html</code></td>
                    <td><code>?format=html</code></td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Endpoints</h2>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/healthz</span>
                </div>
                <p class="endpoint-desc">Health check endpoint. Returns service status.</p>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois/{query}</span>
                </div>
                <p class="endpoint-desc">
                    General WHOIS lookup. Automatically detects query type (domain, IP, or ASN).
                </p>
                <h3>Example</h3>
                <pre><code>GET /api/v1/whois/example.com
GET /api/v1/whois/8.8.8.8
GET /api/v1/whois/AS15169</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois/domain/{domain}</span>
                </div>
                <p class="endpoint-desc">Domain-specific WHOIS lookup.</p>
                <h3>Example</h3>
                <pre><code>GET /api/v1/whois/domain/github.com</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois/ip/{ip}</span>
                </div>
                <p class="endpoint-desc">IP address WHOIS lookup (IPv4 or IPv6).</p>
                <h3>Example</h3>
                <pre><code>GET /api/v1/whois/ip/1.1.1.1
GET /api/v1/whois/ip/2001:4860:4860::8888</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois/asn/{asn}</span>
                </div>
                <p class="endpoint-desc">ASN WHOIS lookup.</p>
                <h3>Example</h3>
                <pre><code>GET /api/v1/whois/asn/AS13335</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois/validate/{query}</span>
                </div>
                <p class="endpoint-desc">
                    Validate a WHOIS query without performing the lookup. 
                    Returns query type and validation status.
                </p>
                <h3>Example</h3>
                <pre><code>GET /api/v1/whois/validate/example.com</code></pre>
                <h3>Response</h3>
                <pre><code>{
  "success": true,
  "data": {
    "query": "example.com",
    "valid": true,
    "type": "domain"
  }
}</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/api/v1/whois/bulk</span>
                </div>
                <p class="endpoint-desc">
                    Bulk WHOIS lookup. Query multiple domains/IPs in a single request. 
                    Requires authentication.
                </p>
                <h3>Request Body</h3>
                <pre><code>{
  "queries": [
    "example.com",
    "8.8.8.8",
    "AS15169"
  ]
}</code></pre>
                <h3>Response</h3>
                <pre><code>{
  "success": true,
  "data": {
    "count": 3,
    "results": [...]
  }
}</code></pre>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/whois-servers</span>
                </div>
                <p class="endpoint-desc">List all known WHOIS servers.</p>
            </div>
            
            <div class="endpoint">
                <div>
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/api/v1/stats</span>
                </div>
                <p class="endpoint-desc">Service statistics and metrics.</p>
            </div>
        </div>
        
        <div class="card">
            <h2>Response Format (JSON)</h2>
            <h3>Success Response</h3>
            <pre><code>{
  "success": true,
  "data": {
    "query": "example.com",
    "type": "domain",
    "server": "whois.iana.org",
    "timestamp": "2024-02-02T14:00:00Z",
    "raw": "Domain Name: EXAMPLE.COM\\n..."
  }
}</code></pre>
            
            <h3>Error Response</h3>
            <pre><code>{
  "success": false,
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Invalid domain format"
  }
}</code></pre>
        </div>
        
        <div class="card">
            <h2>Rate Limiting</h2>
            <p>
                API endpoints are rate-limited to prevent abuse. 
                Rate limits vary by endpoint and authentication status.
            </p>
            <table>
                <tr>
                    <th>User Type</th>
                    <th>Rate Limit</th>
                </tr>
                <tr>
                    <td>Anonymous</td>
                    <td>60 requests/minute</td>
                </tr>
                <tr>
                    <td>Authenticated</td>
                    <td>600 requests/minute</td>
                </tr>
            </table>
        </div>
        
        <div class="nav-links">
            <a href="/" class="btn">← Back to Search</a>
        </div>
    </div>
</body>
</html>`, title, title)
}
