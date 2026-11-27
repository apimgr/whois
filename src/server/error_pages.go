package server

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"

	"github.com/apimgr/whois/src/common/i18n"
)

type statusErrorPageData struct {
	translatablePageData
	TitleKey   string
	MessageKey string
}

var statusErrorTemplate = mustParseTemplate("status-error", "page/error.tmpl")

func statusErrorKeys(status int) (string, string) {
	switch status {
	case http.StatusBadRequest, http.StatusRequestTimeout, http.StatusRequestEntityTooLarge:
		return "errors.bad_request", "errors.bad_request_message"
	case http.StatusUnauthorized:
		return "errors.unauthorized", "errors.unauthorized_message"
	case http.StatusForbidden:
		return "errors.forbidden", "errors.forbidden_message"
	case http.StatusNotFound:
		return "errors.not_found", "errors.not_found_message"
	case http.StatusMethodNotAllowed, http.StatusNotAcceptable, http.StatusUnsupportedMediaType:
		return "errors.method_not_allowed", "errors.method_not_allowed_message"
	case http.StatusConflict, http.StatusGone, http.StatusPreconditionFailed:
		return "errors.conflict", "errors.conflict_message"
	case http.StatusTooManyRequests:
		return "errors.rate_limited", "errors.rate_limited_message"
	case http.StatusBadGateway, http.StatusGatewayTimeout:
		return "errors.bad_gateway", "errors.bad_gateway_message"
	case http.StatusServiceUnavailable:
		return "errors.maintenance", "errors.maintenance_message"
	default:
		return "errors.server_error", "errors.server_error_message"
	}
}

func (s *Server) renderStatusError(w http.ResponseWriter, r *http.Request, status int) {
	var rendered []byte
	err := func() (renderErr error) {
		defer func() {
			if recover() != nil {
				renderErr = errors.New("status error page rendering panicked")
			}
		}()
		titleKey, messageKey := statusErrorKeys(status)
		data := statusErrorPageData{translatablePageData: s.newPageData(w, r), TitleKey: titleKey, MessageKey: messageKey}
		recorder := httptest.NewRecorder()
		if renderErr := s.renderTemplate(statusErrorTemplate, recorder, r, data); renderErr != nil {
			return renderErr
		}
		rendered = recorder.Body.Bytes()
		return nil
	}()
	if err != nil {
		renderHardcodedFallback(s, w, r, status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.setHTMLCacheHeaders(w.Header(), r)
	w.WriteHeader(status)
	_, _ = w.Write(rendered)
}

type bufferedErrorWriter struct {
	dst       http.ResponseWriter
	header    http.Header
	server    *Server
	request   *http.Request
	status    int
	body      bytes.Buffer
	committed bool
}

const errorResponseBufferLimit = 64 * 1024

func newBufferedErrorWriter(dst http.ResponseWriter, server *Server, request *http.Request) *bufferedErrorWriter {
	return &bufferedErrorWriter{dst: dst, header: make(http.Header), server: server, request: request}
}

func (w *bufferedErrorWriter) Header() http.Header { return w.header }
func (w *bufferedErrorWriter) WriteHeader(status int) {
	if w.status == 0 && !w.committed {
		w.status = status
	}
}
func (w *bufferedErrorWriter) Write(body []byte) (int, error) {
	if w.committed {
		if w.status == http.StatusNotModified {
			return len(body), nil
		}
		return w.dst.Write(body)
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.body.Len()+len(body) > errorResponseBufferLimit {
		if err := w.commit(); err != nil {
			return 0, err
		}
		return w.dst.Write(body)
	}
	return w.body.Write(body)
}
func (w *bufferedErrorWriter) commit() error {
	if w.committed {
		return nil
	}
	copyResponseHeaders(w.dst.Header(), w.header)
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	w.server.setHTMLCacheHeaders(w.dst.Header(), w.request)
	w.dst.WriteHeader(status)
	w.committed = true
	if w.body.Len() == 0 {
		w.body.Reset()
		return nil
	}
	_, err := w.dst.Write(w.body.Bytes())
	w.body.Reset()
	return err
}
func (w *bufferedErrorWriter) Flush() {
	if err := w.commit(); err != nil {
		return
	}
	if flusher, ok := w.dst.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buffer := newBufferedErrorWriter(w, s, r)
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
					log.Printf("request panic (%s)\n%s", r.URL.Path, debug.Stack())
				}
			}()
			next.ServeHTTP(buffer, r)
		}()

		status := buffer.status
		if status == 0 {
			status = http.StatusOK
		}
		if buffer.committed {
			return
		}
		if panicked {
			copyErrorHeaders(w.Header(), buffer.header)
			if isHTMLRequest(r) && !isAPIRoute(s, r.URL.Path) {
				s.renderStatusError(w, r, http.StatusInternalServerError)
			} else {
				writeErrorFallback(s, w, r, http.StatusInternalServerError)
			}
			return
		}

		contentType := strings.ToLower(buffer.header.Get("Content-Type"))
		if status >= 400 && strings.Contains(contentType, "text/plain") {
			copyErrorHeaders(w.Header(), buffer.header)
			if isAPIRoute(s, r.URL.Path) || DetectClientType(r) == ClientTypeJSON {
				writeRequestAPIError(w, r, status)
				return
			}
			if isHTMLRequest(r) {
				s.renderStatusError(w, r, status)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("Error: " + http.StatusText(status) + "\n"))
			return
		}
		copyResponseHeaders(w.Header(), buffer.header)
		s.setHTMLCacheHeaders(w.Header(), r)
		w.WriteHeader(status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copyErrorHeaders(dst, src http.Header) {
	for key, values := range src {
		if strings.EqualFold(key, "Content-Type") || strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Content-Range") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isAPIRoute(s *Server, path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, s.config.APIBasePath()+"/") || path == s.config.APIBasePath()
}

func isHTMLRequest(r *http.Request) bool {
	return DetectClientType(r) == ClientTypeHTML
}

func renderHardcodedFallback(s *Server, w http.ResponseWriter, r *http.Request, status int) {
	writeErrorFallback(s, w, r, status)
}

func writeErrorFallback(s *Server, w http.ResponseWriter, r *http.Request, status int) {
	clientType := DetectClientType(r)
	if isAPIRoute(s, r.URL.Path) || clientType == ClientTypeJSON {
		writeRequestAPIError(w, r, status)
		return
	}
	lang := requestErrorLanguage(r)
	titleKey, messageKey := statusErrorKeys(status)
	w.Header().Set("Content-Language", lang)
	addVaryHeader(w.Header(), "Accept-Language")
	if clientType == ClientTypeText {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(translateKey(lang, messageKey) + "\n"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.setHTMLCacheHeaders(w.Header(), r)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><html lang=\"%s\" dir=\"%s\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>%s</title></head><body><main><h1>%s</h1><p>%s</p><p><a href=\"/\">%s</a></p><p><a href=\"/server/help\">%s</a></p></main></body></html>",
		html.EscapeString(lang), html.EscapeString(i18n.Dir(lang)), html.EscapeString(translateKey(lang, titleKey)),
		html.EscapeString(translateKey(lang, "errors.page_heading")), html.EscapeString(translateKey(lang, messageKey)),
		html.EscapeString(translateKey(lang, "errors.home_action")), html.EscapeString(translateKey(lang, "errors.help_action")))
}
