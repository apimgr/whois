package swagger

import (
	"net/http"
	"testing"
)

func TestBuildSpecFromRoutesUsesConfiguredVersion(t *testing.T) {
	routes := []Route{{Method: http.MethodGet, Path: "/api/v9/whois/{query}", OperationID: "whoisLookup", Summary: "WHOIS lookup", Listed: true, Response: APIResponseModel{}}}
	spec := BuildSpecFromRoutes("https://whois.example.test", "test", "/api/v9", routes)
	if _, ok := spec.Paths["/api/v9/whois/{query}"]; !ok {
		t.Fatal("configured API version is missing from the OpenAPI paths")
	}
	if got := spec.Paths["/api/v9/whois/{query}"].Get.OperationID; got != "whoisLookup" {
		t.Fatalf("generated operation ID = %q", got)
	}
}
