package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/email"
	"github.com/apimgr/whois/src/security"
)

func TestSecurityContactSubmissionRequiresCaptchaAndStoresEncryptedReport(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	s.config.Security.EncryptionKey = key
	s.config.ConfigDir = t.TempDir()
	s.config.Pages.Contact.Antispam.MinFillSeconds = 0
	secret, err := s.database.AppSecret(context.Background(), "installation_secret")
	if err != nil {
		t.Fatal(err)
	}
	securityID := securityIDFor(secret, time.Now().Unix()/securityIDWindowSeconds)
	if !s.validSecurityID(context.Background(), securityID, time.Now()) {
		t.Fatal("generated security ID is not valid")
	}
	handler := s.setupRoutes()
	formPath := "/api/v1/server/contact?security_id=" + url.QueryEscape(securityID)
	form := getContactAPIForm(t, handler, formPath)
	challenge := form["captcha"].(map[string]any)
	fields := validSecurityContactFields(t, challenge, form["form_token"].(string), securityID)
	if problem := s.validateContactFields(fields, true); problem != "" {
		t.Fatalf("security contact fields are invalid: %s; fields=%v", problem, fields)
	}

	invalidCaptcha := cloneContactFields(fields)
	invalidCaptcha["captcha_answer"] = "wrong"
	badResponse := postContactAPI(t, handler, formPath, invalidCaptcha)
	if badResponse.Code != http.StatusBadRequest || !strings.Contains(badResponse.Body.String(), `"error": "VALIDATION_FAILED"`) {
		t.Fatalf("invalid CAPTCHA response = %d, %s", badResponse.Code, badResponse.Body.String())
	}

	form = getContactAPIForm(t, handler, formPath)
	challenge = form["captcha"].(map[string]any)
	fields = validSecurityContactFields(t, challenge, form["form_token"].(string), securityID)
	reviewResponse := postContactAPI(t, handler, formPath, fields)
	if reviewResponse.Code != http.StatusOK {
		var challengeCount int
		_ = s.database.Read().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM captcha_challenges WHERE id=?", fields["captcha_id"]).Scan(&challengeCount)
		t.Fatalf("review response = %d, %s; captcha challenge remains=%d", reviewResponse.Code, reviewResponse.Body.String(), challengeCount)
	}
	reviewData := decodeDataMap(t, decodeAPIResponse(t, reviewResponse.Body.String()))
	review := reviewData["review"].(map[string]any)
	reviewToken, ok := reviewData["review_token"].(string)
	if !ok || reviewToken == "" || reviewData["confirm_after_seconds"] != float64(2) {
		t.Fatalf("review gate = %#v", reviewData)
	}

	time.Sleep(2100 * time.Millisecond)
	confirmation := cloneContactFields(fields)
	delete(confirmation, "captcha_id")
	delete(confirmation, "captcha_answer")
	confirmation["step"] = "confirm"
	confirmation["review_token"] = reviewToken
	confirmation["confirmed"] = "true"
	confirmed := postContactAPI(t, handler, formPath, confirmation)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirmation response = %d, %s", confirmed.Code, confirmed.Body.String())
	}
	result := decodeDataMap(t, decodeAPIResponse(t, confirmed.Body.String()))
	trackingID, ok := result["tracking_id"].(string)
	if !ok || !strings.HasPrefix(trackingID, "sec_") || !strings.Contains(result["message"].(string), trackingID) {
		t.Fatalf("confirmed report response = %#v", result)
	}
	if review["type"] != "security" {
		t.Fatalf("review type = %#v, want security", review["type"])
	}

	var bodyEncrypted, bodyAlgorithm, contactEncrypted string
	if err := s.database.Read().QueryRowContext(context.Background(), `SELECT body_enc, body_alg, contact_enc FROM security_reports WHERE tracking_id=?`, trackingID).Scan(&bodyEncrypted, &bodyAlgorithm, &contactEncrypted); err != nil {
		t.Fatalf("read persisted security report: %v", err)
	}
	if bodyAlgorithm != "aes-256-gcm" || strings.Contains(bodyEncrypted, fields["summary"]) || strings.Contains(contactEncrypted, fields["email"]) {
		t.Fatalf("report data was not stored encrypted: algorithm=%q", bodyAlgorithm)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	decryptedBody, err := security.DecryptAESGCM(decodedKey, bodyEncrypted)
	if err != nil || !strings.Contains(decryptedBody, fields["summary"]) {
		t.Fatalf("decrypt stored report: err=%v body=%s", err, decryptedBody)
	}
}

func TestContactSubmissionReviewsCaptchaAndDeliversEmail(t *testing.T) {
	s := newTestServer(t)
	s.config.Pages.Contact.Antispam.MinFillSeconds = 0
	s.config.Contact.DPO.Email = "privacy@example.test"
	listener, message := startContactTestSMTP(t)
	address := listener.Addr().(*net.TCPAddr)
	manager := email.NewEmailManager(t.TempDir())
	manager.Configure("127.0.0.1", address.Port, "", "", "none", "Whois Test", "whois@example.test")
	manager.Enable()
	s.email = manager
	handler := s.setupRoutes()
	formPath := "/api/v1/server/contact?type=privacy"
	form := getContactAPIForm(t, handler, formPath)
	challenge := form["captcha"].(map[string]any)
	answer := simpleContactCaptchaAnswer(t, challenge)
	fields := contactFields{
		"name": "Privacy Requester", "email": "requester@example.test", "type": "privacy", "request_kind": "access",
		"subject": "Personal data request", "message": "Please provide my data.", "form_token": form["form_token"].(string),
		"captcha_id": challenge["captcha_id"].(string), "captcha_answer": answer,
	}
	reviewResponse := postContactAPI(t, handler, formPath, fields)
	if reviewResponse.Code != http.StatusOK {
		t.Fatalf("review response = %d, %s", reviewResponse.Code, reviewResponse.Body.String())
	}
	reviewData := decodeDataMap(t, decodeAPIResponse(t, reviewResponse.Body.String()))
	reviewToken := reviewData["review_token"].(string)
	if reviewToken == "" || reviewData["confirm_after_seconds"] != float64(2) {
		t.Fatalf("review gate = %#v", reviewData)
	}
	time.Sleep(2100 * time.Millisecond)
	confirmation := cloneContactFields(fields)
	delete(confirmation, "captcha_id")
	delete(confirmation, "captcha_answer")
	confirmation["step"] = "confirm"
	confirmation["review_token"] = reviewToken
	confirmation["confirmed"] = "true"
	confirmed := postContactAPI(t, handler, formPath, confirmation)
	if confirmed.Code != http.StatusOK || !strings.Contains(confirmed.Body.String(), `"Thank you for your message.`) {
		t.Fatalf("contact confirmation = %d, %s", confirmed.Code, confirmed.Body.String())
	}
	select {
	case delivered := <-message:
		if !strings.Contains(delivered, "To: privacy@example.test") || !strings.Contains(delivered, "Reply-To: <requester@example.test>") || !strings.Contains(delivered, "Personal data request") {
			t.Fatalf("contact message does not match submitted fields: %s", delivered)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("contact message was not delivered to the configured privacy recipient")
	}
}

func TestReadContactFieldsAcceptsConditionalReportFields(t *testing.T) {
	tests := []struct {
		name   string
		fields contactFields
	}{
		{name: "abuse reason", fields: contactFields{"type": "abuse", "reason": "terms_violation"}},
		{name: "DMCA work", fields: contactFields{"type": "dmca", "copyrighted_work": "Original work"}},
		{name: "privacy request", fields: contactFields{"type": "privacy", "request_kind": "access"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.fields)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/server/contact", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			fields, err := readContactFields(request)
			if err != nil {
				t.Fatalf("read typed report fields: %v", err)
			}
			for name, value := range test.fields {
				if fields[name] != value {
					t.Errorf("field %s = %q, want %q", name, fields[name], value)
				}
			}
		})
	}
}

func TestContactRateLimitReservationsAreAtomic(t *testing.T) {
	s := newTestServer(t)
	s.config.Pages.Contact.Antispam.PerIP = 1
	s.config.Pages.Contact.Antispam.PerEmail = 1
	s.config.Pages.Contact.Antispam.Global = 100
	s.config.Pages.Contact.Antispam.Window = "1h"
	ip := "192.0.2.199"
	address := "atomic-rate-test@example.test"
	keys := []string{"ip:" + ip, "email:" + address, "global"}
	contactAccepted.Lock()
	for _, key := range keys {
		delete(contactAccepted.events, key)
	}
	contactAccepted.Unlock()
	t.Cleanup(func() {
		contactAccepted.Lock()
		defer contactAccepted.Unlock()
		for _, key := range keys {
			delete(contactAccepted.events, key)
		}
	})

	const callers = 32
	start := make(chan struct{})
	results := make(chan string, callers)
	var workers sync.WaitGroup
	workers.Add(callers)
	for range callers {
		go func() {
			defer workers.Done()
			<-start
			results <- s.checkContactRate(ip, address, true)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	accepted, rejected := 0, 0
	for reason := range results {
		if reason == "" {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted != 1 || rejected != callers-1 {
		t.Fatalf("concurrent rate reservations accepted=%d rejected=%d, want 1/%d", accepted, rejected, callers-1)
	}
}

func startContactTestSMTP(t *testing.T) (net.Listener, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	message := make(chan string, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		reader := bufio.NewReader(connection)
		writer := bufio.NewWriter(connection)
		write := func(value string) bool {
			if _, writeErr := fmt.Fprint(writer, value+"\r\n"); writeErr != nil {
				return false
			}
			return writer.Flush() == nil
		}
		if !write("220 localhost ESMTP") {
			return
		}
		var data strings.Builder
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			command := strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(command, "EHLO ") || strings.HasPrefix(command, "HELO "):
				if !write("250 localhost") {
					return
				}
			case strings.HasPrefix(command, "MAIL FROM:") || strings.HasPrefix(command, "RCPT TO:"):
				if !write("250 accepted") {
					return
				}
			case command == "DATA":
				if !write("354 end with <CRLF>.<CRLF>") {
					return
				}
				data.Reset()
				for {
					line, readErr = reader.ReadString('\n')
					if readErr != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "." {
						break
					}
					data.WriteString(line)
				}
				message <- data.String()
				if !write("250 queued") {
					return
				}
			case command == "QUIT":
				write("221 bye")
				return
			default:
				if !write("250 accepted") {
					return
				}
			}
		}
	}()
	return listener, message
}

func getContactAPIForm(t *testing.T, handler http.Handler, path string) map[string]any {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("contact form response = %d, %s", response.Code, response.Body.String())
	}
	return decodeDataMap(t, decodeAPIResponse(t, response.Body.String()))
}

func postContactAPI(t *testing.T, handler http.Handler, path string, fields contactFields) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	request.RemoteAddr = "192.0.2.77:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func validSecurityContactFields(t *testing.T, challenge map[string]any, formToken, securityID string) contactFields {
	t.Helper()
	return contactFields{
		"name": "Security Researcher", "email": "researcher@example.test", "security_id": securityID,
		"component": "api", "severity": "high", "summary": "Example vulnerability", "steps": "Step one", "impact": "Example impact",
		"credit_preference": "no", "coordinated_disclosure_agreement": "true", "form_token": formToken,
		"captcha_id": challenge["captcha_id"].(string), "captcha_answer": simpleContactCaptchaAnswer(t, challenge),
	}
}

func simpleContactCaptchaAnswer(t *testing.T, challenge map[string]any) string {
	t.Helper()
	question, ok := challenge["question"].(string)
	if !ok {
		t.Fatalf("simple CAPTCHA question = %#v", challenge["question"])
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimSpace(question), " = ?"), "+")
	if len(parts) != 2 {
		t.Fatalf("unexpected CAPTCHA challenge %q", question)
	}
	left, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		t.Fatal(err)
	}
	right, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(left + right)
}

func cloneContactFields(fields contactFields) contactFields {
	clone := make(contactFields, len(fields))
	for key, value := range fields {
		clone[key] = value
	}
	return clone
}
