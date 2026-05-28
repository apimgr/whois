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

// firstOctetRIR maps the first octet of an IPv4 address to the responsible RIR server.
// Octets not present fall back to IANAServer (RFC1918, multicast, loopback, etc.).
var firstOctetRIR = func() map[int]Server {
	m := make(map[int]Server, 256)
	for _, o := range []int{3, 4, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 23, 24, 32, 33, 34, 35, 38, 40, 44, 45, 47, 48, 50, 52, 53, 54, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146, 147, 148, 149, 152, 155, 158, 159, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216} {
		m[o] = ARINServer
	}
	for _, o := range []int{2, 5, 25, 31, 37, 46, 51, 57, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217} {
		m[o] = RIPEServer
	}
	for _, o := range []int{1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 150, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223} {
		m[o] = APNICServer
	}
	for _, o := range []int{177, 179, 181, 186, 187, 189, 190, 191, 200, 201} {
		m[o] = LACNICServer
	}
	for _, o := range []int{41, 102, 105, 154, 156, 160, 161, 163, 196, 197} {
		m[o] = AFRINICServer
	}
	return m
}()

// GetServerForIP returns the appropriate WHOIS server for an IP address
func GetServerForIP(ipStr string) Server {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IANAServer
	}

	// IPv6 addresses go to IANA for redirection
	ip4 := ip.To4()
	if ip4 == nil {
		return IANAServer
	}

	if srv, ok := firstOctetRIR[int(ip4[0])]; ok {
		return srv
	}
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
