package main

import (
	"net/http"
	"os"
)

const fixtureResponse = `{"objectClassName":"domain","ldhName":"fixture.example.test","handle":"FIXTURE-1","status":["active"],"events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}],"nameservers":[{"objectClassName":"nameserver","ldhName":"ns1.fixture.example.test"}],"entities":[{"objectClassName":"entity","handle":"FIXTURE-REGISTRAR","roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"99999"}],"vcardArray":["vcard",[["fn",{},"text","Fixture Test Registrar"]]]},{"objectClassName":"entity","roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Fixture Registrant"],["org",{},"text","Fixture Research Group"],["email",{},"text","registrant@example.test"]]]}]}`

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/domain/fixture.example.test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(fixtureResponse))
	})
	if err := http.ListenAndServe("127.0.0.1:65001", mux); err != nil {
		os.Exit(1)
	}
}
