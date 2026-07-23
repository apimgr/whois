package graphql

// buildIntrospectionSchema returns the minimal GraphQL introspection schema
// describing the "health", "stats", and "whois" queries (AI.md PART 14).
func buildIntrospectionSchema() map[string]interface{} {
	return map[string]interface{}{
		"__schema": map[string]interface{}{
			"queryType": map[string]string{"name": "Query"},
			"types": []map[string]interface{}{
				{
					"kind": "OBJECT",
					"name": "Query",
					"fields": []map[string]interface{}{
						{
							"name":        "whois",
							"description": "Look up WHOIS information for a domain, IP, or ASN",
							"args": []map[string]interface{}{
								{"name": "query", "type": map[string]string{"kind": "NON_NULL", "name": "String"}},
							},
							"type": map[string]string{"kind": "OBJECT", "name": "WhoisRecord"},
						},
						{
							"name":        "health",
							"description": "Get server health status",
							"args":        []interface{}{},
							"type":        map[string]string{"kind": "OBJECT", "name": "Health"},
						},
						{
							"name":        "stats",
							"description": "Get server statistics",
							"args":        []interface{}{},
							"type":        map[string]string{"kind": "OBJECT", "name": "Stats"},
						},
					},
				},
				{
					"kind": "OBJECT",
					"name": "WhoisRecord",
					"fields": []map[string]interface{}{
						{"name": "query", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "queryType", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "source", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantName", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantOrg", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrantEmail", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "registrar", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "createdDate", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "expiryDate", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "nameservers", "type": map[string]interface{}{"kind": "LIST", "ofType": map[string]string{"kind": "SCALAR", "name": "String"}}},
					},
				},
				{
					"kind": "OBJECT",
					"name": "Health",
					"fields": []map[string]interface{}{
						{"name": "ok", "type": map[string]string{"kind": "SCALAR", "name": "Boolean"}},
						{"name": "status", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "version", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
						{"name": "uptime", "type": map[string]string{"kind": "SCALAR", "name": "String"}},
					},
				},
				{
					"kind": "OBJECT",
					"name": "Stats",
					"fields": []map[string]interface{}{
						{"name": "totalRequests", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "requests24h", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "domainQueries", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
						{"name": "ipQueries", "type": map[string]string{"kind": "SCALAR", "name": "Int"}},
					},
				},
			},
		},
	}
}
