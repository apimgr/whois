package server

import (
	"fmt"
	"net/http"
	"strings"
)

// handlePublicWHOISPage serves the public WHOIS lookup web interface
// GET /
func (s *Server) handlePublicWHOISPage(w http.ResponseWriter, r *http.Request) {
	// Only serve HTML for root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check Accept header - if JSON requested, return API info
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		s.handleRootAPI(w, r)
		return
	}

	// Serve HTML page
	html := renderPublicWHOISHTML(s.config.BrandingTitle, s.config.BrandingTagline, s.config.BrandingDescription)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleRootAPI returns API information for root endpoint
// GET / (with Accept: application/json)
func (s *Server) handleRootAPI(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"service":     "caswhois",
		"description": "WHOIS lookup service",
		"version":     "0.1.0",
		"endpoints": []string{
			"/healthz - Health check",
			"/api/v1/healthz - API health check",
			"/api/v1/whois/{query} - WHOIS lookup",
			"/api/v1/whois-servers - List WHOIS servers",
			"/api/v1/stats - Service statistics",
		},
	}

	SendSuccess(w, data)
}

// renderPublicWHOISHTML generates the public WHOIS lookup page HTML
func renderPublicWHOISHTML(title, tagline, description string) string {
	if title == "" {
		title = "CASWHOIS"
	}
	if tagline == "" {
		tagline = "Fast, reliable WHOIS lookups"
	}
	if description == "" {
		description = "Look up domain names, IP addresses, and ASN information"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="%s">
    <title>%s - %s</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        
        .container {
            max-width: 800px;
            width: 100%%;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 3rem;
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        h1 {
            font-size: 2.5rem;
            color: #2d3748;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        
        .tagline {
            color: #718096;
            font-size: 1.125rem;
            margin-bottom: 0.5rem;
        }
        
        .description {
            color: #a0aec0;
            font-size: 0.95rem;
        }
        
        .search-form {
            margin: 2rem 0;
        }
        
        .search-container {
            position: relative;
            margin-bottom: 1rem;
        }
        
        .search-input {
            width: 100%%;
            padding: 1rem 1.25rem;
            font-size: 1.125rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            outline: none;
            transition: all 0.2s;
        }
        
        .search-input:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .search-button {
            width: 100%%;
            padding: 1rem;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1.125rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .search-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .search-button:active {
            transform: translateY(0);
        }
        
        .search-button:disabled {
            background: #cbd5e0;
            cursor: not-allowed;
            transform: none;
        }
        
        .examples {
            margin: 1.5rem 0;
            padding: 1rem;
            background: #f7fafc;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .examples-title {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .example-links {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
        }
        
        .example-link {
            color: #667eea;
            text-decoration: none;
            padding: 0.25rem 0.75rem;
            background: white;
            border-radius: 4px;
            font-size: 0.875rem;
            transition: all 0.2s;
            border: 1px solid #e2e8f0;
        }
        
        .example-link:hover {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .result {
            display: none;
            margin-top: 2rem;
            padding: 1.5rem;
            background: #f7fafc;
            border-radius: 8px;
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .result.show {
            display: block;
        }
        
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .result-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #2d3748;
        }
        
        .result-type {
            padding: 0.25rem 0.75rem;
            background: #667eea;
            color: white;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .result-raw {
            background: #2d3748;
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #718096;
        }
        
        .spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 4px solid #e2e8f0;
            border-top-color: #667eea;
            border-radius: 50%%;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .error {
            background: #fed7d7;
            color: #c53030;
            padding: 1rem;
            border-radius: 6px;
            margin-top: 1rem;
            border-left: 4px solid #c53030;
        }
        
        .footer {
            text-align: center;
            margin-top: 2rem;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.875rem;
        }
        
        .footer a {
            color: white;
            text-decoration: none;
            border-bottom: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .footer a:hover {
            border-bottom-color: white;
        }
        
        @media (max-width: 768px) {
            .card {
                padding: 2rem 1.5rem;
            }
            
            h1 {
                font-size: 2rem;
            }
            
            .search-input, .search-button {
                font-size: 1rem;
            }
            
            .example-links {
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>%s</h1>
                <p class="tagline">%s</p>
                <p class="description">%s</p>
            </div>
            
            <div class="search-form">
                <div class="search-container">
                    <input 
                        type="text" 
                        id="searchInput" 
                        class="search-input" 
                        placeholder="Enter domain, IP address, or ASN number..."
                        autofocus
                    >
                </div>
                <button id="searchButton" class="search-button" onclick="performLookup()">
                    Lookup WHOIS
                </button>
            </div>
            
            <div class="examples">
                <div class="examples-title">Try Examples</div>
                <div class="example-links">
                    <a href="#" class="example-link" onclick="lookupExample('example.com'); return false;">example.com</a>
                    <a href="#" class="example-link" onclick="lookupExample('8.8.8.8'); return false;">8.8.8.8</a>
                    <a href="#" class="example-link" onclick="lookupExample('2001:4860:4860::8888'); return false;">2001:4860:4860::8888</a>
                    <a href="#" class="example-link" onclick="lookupExample('AS15169'); return false;">AS15169</a>
                </div>
            </div>
            
            <div id="loading" class="loading" style="display: none;">
                <div class="spinner"></div>
                <p style="margin-top: 1rem;">Looking up WHOIS information...</p>
            </div>
            
            <div id="result" class="result">
                <div class="result-header">
                    <h2 class="result-title" id="resultQuery"></h2>
                    <span class="result-type" id="resultType"></span>
                </div>
                <pre id="resultRaw" class="result-raw"></pre>
            </div>
            
            <div id="error" class="error" style="display: none;"></div>
        </div>
        
        <div class="footer">
            Powered by <a href="/api/v1/healthz">%s API</a>
        </div>
    </div>
    
    <script>
        const searchInput = document.getElementById('searchInput');
        const searchButton = document.getElementById('searchButton');
        const loading = document.getElementById('loading');
        const result = document.getElementById('result');
        const error = document.getElementById('error');
        
        // Enter key handler
        searchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                performLookup();
            }
        });
        
        function lookupExample(query) {
            searchInput.value = query;
            performLookup();
        }
        
        async function performLookup() {
            const query = searchInput.value.trim();
            
            if (!query) {
                showError('Please enter a domain, IP address, or ASN number');
                return;
            }
            
            // Hide previous results
            result.classList.remove('show');
            error.style.display = 'none';
            
            // Show loading
            loading.style.display = 'block';
            searchButton.disabled = true;
            searchButton.textContent = 'Looking up...';
            
            try {
                const response = await fetch('/api/v1/whois/' + encodeURIComponent(query));
                const data = await response.json();
                
                if (response.ok && data.success) {
                    showResult(data.data);
                } else {
                    showError(data.message || 'WHOIS lookup failed');
                }
            } catch (e) {
                showError('Network error: ' + e.message);
            } finally {
                loading.style.display = 'none';
                searchButton.disabled = false;
                searchButton.textContent = 'Lookup WHOIS';
            }
        }
        
        function showResult(data) {
            document.getElementById('resultQuery').textContent = data.query;
            document.getElementById('resultType').textContent = data.type;
            document.getElementById('resultRaw').textContent = data.raw || 'No WHOIS data available';
            result.classList.add('show');
        }
        
        function showError(message) {
            error.textContent = message;
            error.style.display = 'block';
        }
    </script>
</body>
</html>`, description, title, tagline, title, tagline, description, title)
}
