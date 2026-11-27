package swagger

import "testing"

func TestBuildSpecWithAPIBaseUsesConfiguredVersion(t *testing.T) {
	spec := BuildSpecWithAPIBase("https://whois.example.test", "test", "/api/v9")
	if _, ok := spec.Paths["/api/v9/whois/{query}"]; !ok {
		t.Fatal("configured API version is missing from the OpenAPI paths")
	}
	if _, ok := spec.Paths["/api/v1/whois/{query}"]; ok {
		t.Fatal("default API version remains in configured OpenAPI paths")
	}
}
