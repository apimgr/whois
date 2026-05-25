package whois

import (
	"net"
	"strings"
)

// Server represents a WHOIS server
type Server struct {
	Host string
	Port string
}

// DefaultPort is the standard WHOIS port
const DefaultPort = "43"

// Well-known WHOIS servers
var (
	// IANA - root WHOIS server
	IANAServer = Server{Host: "whois.iana.org", Port: DefaultPort}

	// Regional Internet Registries (RIR)
	ARINServer    = Server{Host: "whois.arin.net", Port: DefaultPort}    // North America
	RIPEServer    = Server{Host: "whois.ripe.net", Port: DefaultPort}    // Europe
	APNICServer   = Server{Host: "whois.apnic.net", Port: DefaultPort}   // Asia Pacific
	LACNICServer  = Server{Host: "whois.lacnic.net", Port: DefaultPort}  // Latin America
	AFRINICServer = Server{Host: "whois.afrinic.net", Port: DefaultPort} // Africa
)

// TLD WHOIS servers (common TLDs)
var tldServers = map[string]Server{
	"com":  {Host: "whois.verisign-grs.com", Port: DefaultPort},
	"net":  {Host: "whois.verisign-grs.com", Port: DefaultPort},
	"org":  {Host: "whois.pir.org", Port: DefaultPort},
	"info": {Host: "whois.afilias.net", Port: DefaultPort},
	"biz":  {Host: "whois.biz", Port: DefaultPort},
	"name": {Host: "whois.nic.name", Port: DefaultPort},
	"io":   {Host: "whois.nic.io", Port: DefaultPort},
	"me":   {Host: "whois.nic.me", Port: DefaultPort},
	"co":   {Host: "whois.nic.co", Port: DefaultPort},
	"dev":  {Host: "whois.nic.google", Port: DefaultPort},
	"app":  {Host: "whois.nic.google", Port: DefaultPort},
	
	// Country code TLDs
	"uk":   {Host: "whois.nic.uk", Port: DefaultPort},
	"de":   {Host: "whois.denic.de", Port: DefaultPort},
	"fr":   {Host: "whois.afnic.fr", Port: DefaultPort},
	"nl":   {Host: "whois.domain-registry.nl", Port: DefaultPort},
	"au":   {Host: "whois.auda.org.au", Port: DefaultPort},
	"ca":   {Host: "whois.cira.ca", Port: DefaultPort},
	"jp":   {Host: "whois.jprs.jp", Port: DefaultPort},
	"cn":   {Host: "whois.cnnic.cn", Port: DefaultPort},
	"ru":   {Host: "whois.tcinet.ru", Port: DefaultPort},
	"br":   {Host: "whois.registro.br", Port: DefaultPort},
}

// Address returns the server address (host:port)
func (s Server) Address() string {
	return net.JoinHostPort(s.Host, s.Port)
}

// GetTLDServer returns the WHOIS server for a given TLD
func GetTLDServer(tld string) (Server, bool) {
	tld = strings.ToLower(strings.TrimPrefix(tld, "."))
	server, ok := tldServers[tld]
	return server, ok
}

// GetServerForDomain returns the appropriate WHOIS server for a domain
func GetServerForDomain(domain string) Server {
	// Extract TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		// Invalid domain, use IANA
		return IANAServer
	}

	tld := parts[len(parts)-1]
	
	// Check if we have a specific server for this TLD
	if server, ok := GetTLDServer(tld); ok {
		return server
	}

	// Fall back to IANA
	return IANAServer
}

// GetServerForIP returns the appropriate WHOIS server for an IP address
func GetServerForIP(ipStr string) Server {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IANAServer
	}

	// For now, use IANA which will redirect to appropriate RIR
	// TODO: Implement smart RIR selection based on IP ranges
	return IANAServer
}

// GetServerForASN returns the appropriate WHOIS server for an ASN
func GetServerForASN(asn string) Server {
	// ASNs are managed by RIRs, IANA can redirect
	return IANAServer
}

// GetAllRIRServers returns all RIR servers
func GetAllRIRServers() []Server {
	return []Server{
		ARINServer,
		RIPEServer,
		APNICServer,
		LACNICServer,
		AFRINICServer,
	}
}
