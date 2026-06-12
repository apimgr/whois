// Package data embeds application JSON data files (AI.md PART 7).
package data

import _ "embed"

//go:embed whois-servers.json
var WHOISServersJSON []byte
