package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// alwaysTrustedCIDRs is the set of CIDRs that are always trusted as reverse-proxy
// peers, regardless of the trusted_proxies.additional config (AI.md PART 12).
var alwaysTrustedCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"169.254.0.0/16",
	"fe80::/10",
}

// isTrustedPeer reports whether peerIP is in the always-trusted private ranges or
// in the additional allow-list from trusted_proxies config (AI.md PART 12).
// DNS-name entries in additional are not resolved here — callers should pre-resolve
// them at startup. IP and CIDR string formats are supported.
func isTrustedPeer(peerIP string, additional []string) bool {
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return false
	}
	for _, cidr := range alwaysTrustedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	for _, entry := range additional {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			if entryIP := net.ParseIP(entry); entryIP != nil && entryIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// IsTrustedPeer is the exported form of isTrustedPeer for use outside this package.
func IsTrustedPeer(peerIP string, additional []string) bool {
	return isTrustedPeer(peerIP, additional)
}

// GetURLVars resolves the effective proto, fqdn, and port for the given request.
//
// Resolution order per AI.md PART 12:
//
// FQDN:
//
//	Priority 0 – Tor request (Host == tor.onion_address); always http, no port
//	Priority 1 – X-Forwarded-Host (trusted peer only)
//	Priority 2 – X-Real-Host / X-Original-Host (trusted peer only)
//	Priority 3 – r.Host
//	Priority 4 – server.fqdn from config
//
// Proto (trusted peer only):
//
//	Priority 1 – X-Forwarded-Proto
//	Priority 2 – X-Forwarded-Ssl=on / X-Url-Scheme
//	Priority 3 – "https" if TLS is enabled in config; else "http"
//
// Port:
//
//	Priority 1 – X-Forwarded-Port (trusted peer only)
//	Priority 2 – port embedded in Host
//	Standard ports 80 and 443 are always stripped (never appended).
func (s *Server) GetURLVars(r *http.Request) (proto, fqdn, port string) {
	peerHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	trusted := isTrustedPeer(peerHost, s.config.TrustedProxies.Additional)

	// Priority 0: Tor detection bypasses the proxy header gate entirely.
	if onionAddr := s.config.Tor.OnionAddress; onionAddr != "" {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == onionAddr {
			return "http", onionAddr, ""
		}
	}

	// Resolve FQDN from proxy headers (trusted peers only) or r.Host.
	if trusted {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			fqdn = strings.TrimSpace(strings.SplitN(xfh, ",", 2)[0])
		} else if v := r.Header.Get("X-Real-Host"); v != "" {
			fqdn = strings.TrimSpace(v)
		} else if v := r.Header.Get("X-Original-Host"); v != "" {
			fqdn = strings.TrimSpace(v)
		}
	}
	if fqdn == "" {
		fqdn = r.Host
	}
	// Split port from fqdn if embedded.
	if strings.Contains(fqdn, ":") {
		if h, p, err := net.SplitHostPort(fqdn); err == nil {
			fqdn = h
			port = p
		}
	}
	if fqdn == "" {
		fqdn = s.config.FQDN
	}

	// Resolve proto from proxy headers (trusted peers only) or TLS config.
	if trusted {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			proto = strings.ToLower(strings.TrimSpace(strings.SplitN(v, ",", 2)[0]))
		} else if r.Header.Get("X-Forwarded-Ssl") == "on" {
			proto = "https"
		} else if v := r.Header.Get("X-Url-Scheme"); v != "" {
			proto = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if proto == "" {
		if s.config.TLS.Enabled {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	// Resolve port from X-Forwarded-Port (trusted peer only) or keep the embedded one.
	if port == "" && trusted {
		if v := r.Header.Get("X-Forwarded-Port"); v != "" {
			port = strings.TrimSpace(v)
		}
	}
	// Strip standard ports — never include :80 or :443 in generated URLs.
	if port == "80" || port == "443" {
		port = ""
	}
	return proto, fqdn, port
}

// BuildURL constructs a full absolute URL for the given path.
// :80 and :443 are never included per AI.md PART 12.
func (s *Server) BuildURL(r *http.Request, urlPath string) string {
	proto, fqdn, port := s.GetURLVars(r)
	if port == "" {
		return fmt.Sprintf("%s://%s%s", proto, fqdn, urlPath)
	}
	return fmt.Sprintf("%s://%s:%s%s", proto, fqdn, port, urlPath)
}
