package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTorControlRequiresLoopbackAndExactMethods(t *testing.T) {
	s := newTestServer(t)
	for _, test := range []struct {
		name       string
		remoteAddr string
		method     string
		path       string
	}{
		{name: "remote peer", remoteAddr: "192.0.2.1:1234", method: http.MethodGet, path: "/server/tor/status"},
		{name: "wrong method", remoteAddr: "127.0.0.1:1234", method: http.MethodPost, path: "/server/tor/status"},
		{name: "unknown route", remoteAddr: "127.0.0.1:1234", method: http.MethodGet, path: "/server/tor/unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			req.RemoteAddr = test.remoteAddr
			rec := httptest.NewRecorder()
			s.handleTorControl(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTorControlValidatesBodiesAndConfirmation(t *testing.T) {
	s := newTestServer(t)
	for _, test := range []struct {
		name   string
		path   string
		body   string
		status int
		code   string
	}{
		{name: "unknown field", path: "/server/tor/regenerate", body: `{"confirm":true,"extra":1}`, status: http.StatusBadRequest, code: ErrBadRequest},
		{name: "missing confirm", path: "/server/tor/regenerate", body: `{}`, status: http.StatusBadRequest, code: ErrValidationFailed},
		{name: "missing prefix", path: "/server/tor/vanity/start", body: `{}`, status: http.StatusBadRequest, code: ErrValidationFailed},
		{name: "relative import", path: "/server/tor/import-keys", body: `{"path":"keys","confirm":true}`, status: http.StatusBadRequest, code: ErrValidationFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			req.RemoteAddr = "[::1]:1234"
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.handleTorControl(rec, req)
			if rec.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, test.status, rec.Body.String())
			}
			var response APIResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.Error != test.code {
				t.Errorf("error = %q, want %q", response.Error, test.code)
			}
		})
	}
}

func TestTorControlStatusAndValidation(t *testing.T) {
	s := newTestServer(t)
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/server/tor/status"},
		{method: http.MethodPost, path: "/server/tor/validate"},
	} {
		req := httptest.NewRequest(test.method, test.path, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		s.handleTorControl(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s status = %d: %s", test.method, test.path, rec.Code, rec.Body.String())
		}
		var response APIResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode %s response: %v", test.path, err)
		}
		if !response.OK {
			t.Errorf("%s response is not successful: %+v", test.path, response)
		}
	}
}

func TestTorControlQueuesVanityStart(t *testing.T) {
	s := newTestServer(t)
	s.torActions = make(chan torActionRequest, 1)
	req := httptest.NewRequest(http.MethodPost, "/server/tor/vanity/start", strings.NewReader(`{"prefix":"abc","workers":2}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.handleTorControl(rec, req)
		close(done)
	}()
	queued := <-s.torActions
	if queued.Action != "vanity-start" || queued.Prefix != "abc" || queued.Workers != 2 {
		t.Fatalf("queued action = %+v", queued)
	}
	queued.Reply <- torActionResult{Data: map[string]any{"state": "running", "prefix": "abc", "workers": 2}}
	<-done
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
}
