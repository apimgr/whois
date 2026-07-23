package swagger

// buildPaths returns the documented route annotations for the WHOIS API
// (AI.md PART 13, PART 14).
func buildPaths() map[string]PathItem {
	return map[string]PathItem{
		"/api/v1/server/healthz": {
			Get: &Operation{
				Summary:     "Health check",
				Description: "Returns server health status and component checks.",
				OperationID: "getHealth",
				Tags:        []string{"Server"},
				Responses: map[string]Response{
					"200": {
						Description: "Server is healthy",
						Content: map[string]MediaType{
							"application/json": {Schema: Schema{Ref: "#/components/schemas/HealthResponse"}},
						},
					},
				},
			},
		},
		"/api/v1/whois/{query}": {
			Get: &Operation{
				Summary:     "Auto-detect WHOIS lookup",
				Description: "Performs a WHOIS lookup, auto-detecting whether the query is a domain, IP address, or ASN.",
				OperationID: "whoisLookup",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "query", In: "path", Description: "Domain, IP address, or ASN to look up", Required: true, Schema: Schema{Type: "string"}},
				},
				Responses: map[string]Response{
					"200": {
						Description: "WHOIS data retrieved",
						Content: map[string]MediaType{
							"application/json": {Schema: Schema{Ref: "#/components/schemas/WhoisResponse"}},
						},
					},
					"400": {Description: "Invalid query format"},
					"404": {Description: "No WHOIS data found"},
					"429": {Description: "Rate limit exceeded"},
				},
			},
		},
		"/api/v1/whois/domain/{domain}": {
			Get: &Operation{
				Summary:     "Domain WHOIS lookup",
				Description: "Performs a WHOIS lookup for a domain name.",
				OperationID: "domainLookup",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "domain", In: "path", Description: "Domain name to look up", Required: true, Schema: Schema{Type: "string"}},
				},
				Responses: map[string]Response{
					"200": {Description: "Domain WHOIS data"},
					"400": {Description: "Invalid domain"},
					"404": {Description: "Domain not found"},
				},
			},
		},
		"/api/v1/whois/ip/{ip}": {
			Get: &Operation{
				Summary:     "IP WHOIS lookup",
				Description: "Performs a WHOIS lookup for an IP address (IPv4 or IPv6).",
				OperationID: "ipLookup",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "ip", In: "path", Description: "IP address to look up", Required: true, Schema: Schema{Type: "string"}},
				},
				Responses: map[string]Response{
					"200": {Description: "IP WHOIS data"},
					"400": {Description: "Invalid IP address"},
					"404": {Description: "No data found"},
				},
			},
		},
		"/api/v1/whois/asn/{asn}": {
			Get: &Operation{
				Summary:     "ASN WHOIS lookup",
				Description: "Performs a WHOIS lookup for an Autonomous System Number.",
				OperationID: "asnLookup",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "asn", In: "path", Description: "ASN (with or without AS prefix)", Required: true, Schema: Schema{Type: "string"}},
				},
				Responses: map[string]Response{
					"200": {Description: "ASN WHOIS data"},
					"400": {Description: "Invalid ASN"},
					"404": {Description: "ASN not found"},
				},
			},
		},
		"/api/v1/whois/validate/{query}": {
			Get: &Operation{
				Summary:     "Validate query without lookup",
				Description: "Validates a query and returns the detected type without performing the actual lookup.",
				OperationID: "validateQuery",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "query", In: "path", Description: "Query to validate", Required: true, Schema: Schema{Type: "string"}},
				},
				Responses: map[string]Response{
					"200": {Description: "Query is valid"},
					"400": {Description: "Query is invalid"},
				},
			},
		},
		"/api/v1/whois/search": {
			Get: &Operation{
				Summary:     "Search by owner/registrant",
				Description: "Searches the local WHOIS database by registrant name, org, or email.",
				OperationID: "ownerSearch",
				Tags:        []string{"WHOIS"},
				Parameters: []Parameter{
					{Name: "owner", In: "query", Description: "Owner/registrant to search for", Required: true, Schema: Schema{Type: "string"}},
					{Name: "page", In: "query", Description: "Page number", Schema: Schema{Type: "integer"}},
					{Name: "limit", In: "query", Description: "Results per page (max 250)", Schema: Schema{Type: "integer"}},
				},
				Responses: map[string]Response{
					"200": {Description: "Search results"},
					"400": {Description: "Invalid search parameters"},
				},
			},
		},
		"/api/v1/whois/bulk": {
			Post: &Operation{
				Summary:     "Bulk WHOIS lookup",
				Description: "Performs WHOIS lookups for multiple queries. Requires server token.",
				OperationID: "bulkLookup",
				Tags:        []string{"WHOIS"},
				Security:    []SecurityReq{{"bearerAuth": {}}},
				RequestBody: &RequestBody{
					Required: true,
					Content: map[string]MediaType{
						"application/json": {Schema: Schema{Ref: "#/components/schemas/BulkRequest"}},
					},
				},
				Responses: map[string]Response{
					"200": {Description: "Bulk lookup results"},
					"401": {Description: "Missing or invalid token"},
					"400": {Description: "Invalid request body"},
				},
			},
		},
		"/api/v1/whois-servers": {
			Get: &Operation{
				Summary:     "List WHOIS servers",
				Description: "Returns the list of known WHOIS servers by TLD.",
				OperationID: "listWhoisServers",
				Tags:        []string{"Server"},
				Responses: map[string]Response{
					"200": {Description: "WHOIS server list"},
				},
			},
		},
		"/api/v1/server/stats": {
			Get: &Operation{
				Summary:     "Server statistics",
				Description: "Returns aggregate server statistics (public-safe).",
				OperationID: "getStats",
				Tags:        []string{"Server"},
				Responses: map[string]Response{
					"200": {Description: "Server statistics"},
				},
			},
		},
		"/api/v1/server/schedulers": {
			Get: &Operation{
				Summary:     "List scheduler tasks",
				Description: "Returns configured scheduler tasks and their status. Requires server token.",
				OperationID: "listSchedulerTasks",
				Tags:        []string{"Server"},
				Security:    []SecurityReq{{"bearerAuth": {}}},
				Responses: map[string]Response{
					"200": {Description: "Scheduler task list"},
					"401": {Description: "Missing or invalid token"},
				},
			},
		},
		"/api/v1/server/backups": {
			Get: &Operation{
				Summary:     "List backups",
				Description: "Returns backup history. Requires server token.",
				OperationID: "listBackups",
				Tags:        []string{"Server"},
				Security:    []SecurityReq{{"bearerAuth": {}}},
				Responses: map[string]Response{
					"200": {Description: "Backup list"},
					"401": {Description: "Missing or invalid token"},
				},
			},
		},
		"/api/autodiscover": {
			Get: &Operation{
				Summary:     "Server autodiscovery",
				Description: "Returns server info and CLI version for auto-update.",
				OperationID: "autodiscover",
				Tags:        []string{"Server"},
				Responses: map[string]Response{
					"200": {Description: "Server autodiscovery info"},
				},
			},
		},
	}
}

// buildComponents returns the reusable OpenAPI components (security schemes
// and schemas) for the WHOIS API.
func buildComponents() Components {
	return Components{
		SecuritySchemes: map[string]SecurityScheme{
			"bearerAuth": {
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "token",
				Description:  "Server token (Authorization: Bearer {server.token})",
			},
		},
		Schemas: map[string]Schema{
			"HealthResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"ok":         {Type: "boolean"},
					"status":     {Type: "string"},
					"version":    {Type: "string"},
					"commit":     {Type: "string"},
					"build_date": {Type: "string"},
					"uptime":     {Type: "string"},
					"mode":       {Type: "string"},
					"database":   {Type: "string"},
					"cache":      {Type: "string"},
				},
			},
			"WhoisResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"ok":   {Type: "boolean"},
					"data": {Ref: "#/components/schemas/WhoisRecord"},
				},
			},
			"WhoisRecord": {
				Type: "object",
				Properties: map[string]Schema{
					"query":              {Type: "string"},
					"query_type":         {Type: "string"},
					"source":             {Type: "string"},
					"registrant_name":    {Type: "string"},
					"registrant_org":     {Type: "string"},
					"registrant_email":   {Type: "string"},
					"registrant_country": {Type: "string"},
					"registrar":          {Type: "string"},
					"created_date":       {Type: "string", Format: "date-time"},
					"updated_date":       {Type: "string", Format: "date-time"},
					"expiry_date":        {Type: "string", Format: "date-time"},
					"nameservers":        {Type: "array", Items: &Schema{Type: "string"}},
					"status":             {Type: "array", Items: &Schema{Type: "string"}},
				},
			},
			"BulkRequest": {
				Type: "object",
				Properties: map[string]Schema{
					"queries": {Type: "array", Items: &Schema{Type: "string"}},
				},
			},
		},
	}
}
