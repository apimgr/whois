package graphql

import (
	"context"
	"fmt"
)

// resolveHealthQuery returns health data for the "health" GraphQL query.
func resolveHealthQuery(health HealthInfo) GraphQLResponse {
	return GraphQLResponse{
		Data: map[string]interface{}{
			"health": map[string]interface{}{
				"ok":      health.OK,
				"status":  health.Status,
				"version": health.Version,
				"uptime":  health.Uptime,
			},
		},
	}
}

// resolveStatsQuery returns stats data for the "stats" GraphQL query.
func resolveStatsQuery(stats StatsInfo) GraphQLResponse {
	return GraphQLResponse{
		Data: map[string]interface{}{
			"stats": map[string]interface{}{
				"totalRequests": stats.TotalRequests,
				"requests24h":   stats.Requests24h,
				"domainQueries": stats.DomainQueries,
				"ipQueries":     stats.IPQueries,
			},
		},
	}
}

// resolveWhoisQuery performs a WHOIS lookup for the "whois" GraphQL query.
func resolveWhoisQuery(ctx context.Context, query string, lookup LookupFunc) GraphQLResponse {
	if lookup == nil {
		return GraphQLResponse{
			Errors: []GraphQLError{{Message: "WHOIS lookup service not available"}},
		}
	}

	result, err := lookup(ctx, query)
	if err != nil {
		return GraphQLResponse{
			Errors: []GraphQLError{{Message: fmt.Sprintf("Lookup failed: %v", err)}},
		}
	}

	return GraphQLResponse{
		Data: map[string]interface{}{
			"whois": map[string]interface{}{
				"query":           result.Query,
				"queryType":       result.QueryType,
				"source":          result.Source,
				"registrantName":  result.RegistrantName,
				"registrantOrg":   result.RegistrantOrg,
				"registrantEmail": result.RegistrantEmail,
				"registrar":       result.Registrar,
				"createdDate":     result.CreatedDate,
				"expiryDate":      result.ExpiryDate,
				"nameservers":     result.Nameservers,
			},
		},
	}
}
