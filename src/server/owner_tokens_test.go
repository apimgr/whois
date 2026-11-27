package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/apimgr/whois/src/config"
)

func TestOwnerTokenIssueListAndRevealAPI(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	s.config.Security.EncryptionKey = key

	issueRequest := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/tokens/primary", nil)
	issueResponse := httptest.NewRecorder()
	s.handleIssuePrimaryTokenAPI(issueResponse, issueRequest)
	if issueResponse.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201: %s", issueResponse.Code, issueResponse.Body.String())
	}
	var issued struct {
		Data struct {
			OwnerToken string `json:"owner_token"`
			OwnerID    string `json:"owner_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(issueResponse.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode issue response: %v", err)
	}
	if len(issued.Data.OwnerToken) != 36 || !strings.HasPrefix(issued.Data.OwnerToken, "own_") {
		t.Fatalf("issued token has invalid format: %q", issued.Data.OwnerToken)
	}
	if issued.Data.OwnerID == "" {
		t.Fatal("issue response omitted owner id")
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/tokens", nil)
	listRequest.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	listResponse := httptest.NewRecorder()
	s.handleListOwnerTokensAPI(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200: %s", listResponse.Code, listResponse.Body.String())
	}
	if strings.Contains(listResponse.Body.String(), issued.Data.OwnerToken) {
		t.Fatal("token list exposed the raw owner token")
	}
	if strings.Contains(listResponse.Body.String(), issued.Data.OwnerToken[:12]) || !strings.Contains(listResponse.Body.String(), "own_••") {
		t.Fatalf("token list did not use the required masked value: %s", listResponse.Body.String())
	}

	revealRequest := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/tokens/primary/reveal", nil)
	revealRequest.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	revealResponse := httptest.NewRecorder()
	s.handleRevealPrimaryTokenAPI(revealResponse, revealRequest)
	if revealResponse.Code != http.StatusOK || !strings.Contains(revealResponse.Body.String(), issued.Data.OwnerToken) {
		t.Fatalf("reveal response did not return token: status=%d body=%s", revealResponse.Code, revealResponse.Body.String())
	}
}

func TestOwnerTokenLastUsedIsFlushedFromMemory(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	s.config.Security.EncryptionKey = key
	_, raw, err := s.issuePrimaryToken(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("issuePrimaryToken: %v", err)
	}
	record, err := s.lookupOwnerToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("lookupOwnerToken: %v", err)
	}
	if !record.LastUsed.Valid {
		t.Fatal("lookup did not expose the buffered last-used timestamp")
	}
	var stored sql.NullInt64
	if err := s.database.Read().QueryRow(`SELECT last_used_at FROM api_tokens WHERE id = ?`, record.ID).Scan(&stored); err != nil {
		t.Fatalf("read last_used_at before flush: %v", err)
	}
	if stored.Valid {
		t.Fatal("last_used_at was written during the request instead of being buffered")
	}
	if err := s.flushHotCounters(context.Background()); err != nil {
		t.Fatalf("flush hot counters: %v", err)
	}
	if err := s.database.Read().QueryRow(`SELECT last_used_at FROM api_tokens WHERE id = ?`, record.ID).Scan(&stored); err != nil {
		t.Fatalf("read last_used_at after flush: %v", err)
	}
	if !stored.Valid {
		t.Fatal("flush did not persist last_used_at")
	}
}

func TestOwnerTokenPageUsesCookieAndCSRF(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	s.config.Security.EncryptionKey = key
	_, raw, err := s.issuePrimaryToken(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("issuePrimaryToken: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/server/preferences/tokens", nil)
	request.AddCookie(&http.Cookie{Name: ownerTokenCookieName, Value: raw})
	response := httptest.NewRecorder()
	s.handleOwnerTokensPage(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("page status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Primary token") || !strings.Contains(response.Body.String(), "csrf_token") {
		t.Fatal("owner token page omitted primary token controls or CSRF fields")
	}
	if strings.Contains(response.Body.String(), raw) {
		t.Fatal("normal token page load exposed the raw token")
	}
}

func TestLinkedTokenAPILifecycle(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	s.config.Security.EncryptionKey = key
	handler := s.setupRoutes()
	issue := httptest.NewRecorder()
	issueReq := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/tokens/primary", nil)
	issueReq.Header.Set("Accept", "application/json")
	handler.ServeHTTP(issue, issueReq)
	var issued struct {
		Data struct {
			OwnerToken string `json:"owner_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil || issued.Data.OwnerToken == "" {
		t.Fatalf("decode primary token response: %v: %s", err, issue.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/tokens", bytes.NewBufferString(`{"name":"automation","expires":"7d"}`))
	createReq.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Accept", "application/json")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, createReq)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", created.Code, created.Body.String())
	}
	var linked struct {
		Data struct {
			ID          string `json:"id"`
			LinkedToken string `json:"linked_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &linked); err != nil || linked.Data.ID == "" || linked.Data.LinkedToken == "" {
		t.Fatalf("decode linked token response: %v: %s", err, created.Body.String())
	}
	base := "/api/v1/server/preferences/tokens/" + linked.Data.ID

	rotateReq := httptest.NewRequest(http.MethodPost, base+"/rotate", nil)
	rotateReq.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	rotateReq.Header.Set("Accept", "application/json")
	rotated := httptest.NewRecorder()
	handler.ServeHTTP(rotated, rotateReq)
	if rotated.Code != http.StatusOK || strings.Contains(rotated.Body.String(), linked.Data.LinkedToken) {
		t.Fatalf("rotate did not replace the token: status=%d body=%s", rotated.Code, rotated.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPatch, "/api/v1/server/preferences/tokens/"+linked.Data.ID, bytes.NewBufferString(`{"name":"renamed","expires":"never"}`))
	updateReq.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Accept", "application/json")
	updated := httptest.NewRecorder()
	handler.ServeHTTP(updated, updateReq)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"name": "renamed"`) {
		t.Fatalf("update failed: status=%d body=%s", updated.Code, updated.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/server/preferences/tokens/"+linked.Data.ID, nil)
	revokeReq.Header.Set("Authorization", "Bearer "+issued.Data.OwnerToken)
	revokeReq.Header.Set("Accept", "application/json")
	revoked := httptest.NewRecorder()
	handler.ServeHTTP(revoked, revokeReq)
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), `"status": "revoked"`) {
		t.Fatalf("revoke failed: status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestConcurrentLinkedTokenCreationRespectsOwnerLimit(t *testing.T) {
	s := newTestServer(t)
	key, err := config.GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey: %v", err)
	}
	s.config.Security.EncryptionKey = key
	s.config.Tokens.MaxLinked = 1
	ownerID, primary, err := s.issuePrimaryToken(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("issuePrimaryToken: %v", err)
	}

	const requests = 12
	statuses := make(chan int, requests)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences/tokens", strings.NewReader(fmt.Sprintf(`{"name":"worker-%d"}`, index)))
			request.Header.Set("Authorization", "Bearer "+primary)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			s.handleCreateLinkedTokenAPI(response, request)
			statuses <- response.Code
		}(i)
	}
	close(start)
	wg.Wait()
	close(statuses)

	created, conflicted := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("concurrent create status = %d, want 201 or 409", status)
		}
	}
	if created != 1 || conflicted != requests-1 {
		t.Fatalf("concurrent create results: %d created, %d conflicts; want 1 created and %d conflicts", created, conflicted, requests-1)
	}
	var active int
	if err := s.database.Read().QueryRow(`SELECT COUNT(*) FROM api_tokens WHERE owner_id = ? AND kind = 'linked' AND revoked_at IS NULL`, ownerID).Scan(&active); err != nil {
		t.Fatalf("count linked tokens: %v", err)
	}
	if active != 1 {
		t.Fatalf("active linked-token count = %d, want 1", active)
	}
}
