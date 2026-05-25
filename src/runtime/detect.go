package runtime

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// RuntimeInfo holds detected runtime information
type RuntimeInfo struct {
	// Host information
	Hostname string
	FQDN     string

	// Resources
	CPUCores int
	// Memory will be implemented with OS-specific code

	// Network
	PrimaryIPv4 string
	PrimaryIPv6 string
}

// Detect gathers runtime information
func Detect() *RuntimeInfo {
	info := &RuntimeInfo{
		CPUCores: runtime.NumCPU(),
	}

	// Hostname detection
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// FQDN detection
	info.FQDN = GetFQDN()

	// Network detection
	info.PrimaryIPv4 = getGlobalIPv4()
	info.PrimaryIPv6 = getGlobalIPv6()

	return info
}

// GetFQDN returns the fully qualified domain name
func GetFQDN() string {
	// 1. DOMAIN env var (explicit user override, comma-separated)
	if domain := os.Getenv("DOMAIN"); domain != "" {
		// Return first domain as primary
		if idx := strings.Index(domain, ","); idx > 0 {
			return strings.TrimSpace(domain[:idx])
		}
		return domain
	}

	// 2. os.Hostname() - cross-platform (Linux, macOS, Windows, BSD)
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		if !isLoopback(hostname) {
			return hostname
		}
	}

	// 3. $HOSTNAME env var (skip loopback)
	if hostname := os.Getenv("HOSTNAME"); hostname != "" {
		if !isLoopback(hostname) {
			return hostname
		}
	}

	// 4. Global IPv6 (preferred for modern networks)
	if ipv6 := getGlobalIPv6(); ipv6 != "" {
		return ipv6
	}

	// 5. Global IPv4
	if ipv4 := getGlobalIPv4(); ipv4 != "" {
		return ipv4
	}

	// Last resort (not recommended)
	return "localhost"
}

// isLoopback checks if host is a loopback address
func isLoopback(host string) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// getGlobalIPv6 returns first public IPv6 address
// Excludes: loopback (::1), link-local (fe80::/10), unique local (fc00::/7)
func getGlobalIPv6() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			// Must be IPv6 (not IPv4), globally routable, and not private
			if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}

// getGlobalIPv4 returns first public IPv4 address
// Excludes: loopback (127.0.0.0/8), private (10/8, 172.16/12, 192.168/16), link-local (169.254/16)
func getGlobalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP
			// Must be IPv4, globally routable, and not private
			// Note: IsGlobalUnicast() alone is NOT enough for IPv4 (returns true for private)
			if ip4 := ip.To4(); ip4 != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip4.String()
			}
		}
	}
	return ""
}

// IsPublicIP checks if an IP is publicly routable (not private, loopback, or link-local)
func IsPublicIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// GetAllDomains returns all domains from DOMAIN env var
// Used for CORS configuration and SSL certificates
func GetAllDomains() []string {
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ",")
	domains := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := strings.TrimSpace(p); d != "" {
			domains = append(domains, d)
		}
	}
	return domains
}
