package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/apimgr/whois/src/email"
	"github.com/apimgr/whois/src/security"
)

const contactBodyLimit = 256 << 10

var contactTokenState = struct {
	sync.Mutex
	used map[string]time.Time
}{used: map[string]time.Time{}}
var contactEmailPattern = regexp.MustCompile(`^[^\s,;<>@]+@[^\s,;<>@]+\.[^\s,;<>@]+$`)

func loadResearcherPGPKey(ctx context.Context, supplied string) ([]byte, error) {
	var data []byte
	if strings.HasPrefix(supplied, "https://") {
		u, err := url.Parse(supplied)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" && u.Port() != "443" {
			return nil, fmt.Errorf("invalid HTTPS key URL")
		}
		host := u.Hostname()
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("key host could not be resolved")
		}
		var selected net.IP
		for _, ip := range ips {
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return nil, fmt.Errorf("key host resolves to a non-public address")
			}
			if selected == nil {
				selected = ip
			}
		}
		transport := &http.Transport{DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(host, "443") {
				return nil, fmt.Errorf("unexpected key server address")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, network, net.JoinHostPort(selected.String(), "443"))
		}}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("fetch researcher key: %w", err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("key server returned HTTP %d", response.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		if err != nil || len(data) > 1<<20 {
			return nil, fmt.Errorf("researcher key response exceeds size limit or could not be read")
		}
	} else {
		data = []byte(supplied)
	}
	if err := security.ValidatePGPPublicKey(data); err != nil {
		return nil, err
	}
	return data, nil
}

type contactFields map[string]string

func (s *Server) contactSecret(ctx context.Context) ([]byte, error) {
	if s.database == nil {
		return nil, fmt.Errorf("contact signing secret unavailable")
	}
	return s.database.AppSecret(ctx, "installation_secret")
}

func (s *Server) contactSecrets(ctx context.Context) ([][]byte, error) {
	current, err := s.contactSecret(ctx)
	if err != nil {
		return nil, err
	}
	secrets := [][]byte{current}
	var encoded, until string
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='installation_secret_previous'`).Scan(&encoded); err != nil {
		return secrets, nil
	}
	if err := s.database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name='installation_secret_previous_until'`).Scan(&until); err != nil {
		return secrets, nil
	}
	deadline, err := time.Parse(time.RFC3339, until)
	if err != nil || !time.Now().UTC().Before(deadline) {
		return secrets, nil
	}
	previous, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil && len(previous) == 32 {
		secrets = append(secrets, previous)
	}
	return secrets, nil
}

func (s *Server) issueContactToken(ctx context.Context, purpose string, fields contactFields, flags string, now time.Time) (string, error) {
	secret, err := s.contactSecret(ctx)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	issued := now.Unix()
	bodyHash := ""
	if fields != nil {
		sum := sha256.Sum256([]byte(normalizedContactFields(fields)))
		bodyHash = hex.EncodeToString(sum[:])
	}
	message := fmt.Sprintf("contact-review|%d|%s|%s|%s", issued, nonce, flags, bodyHash)
	if purpose == "contact-form" {
		message = fmt.Sprintf("contact-form|%d|%s", issued, nonce)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(message))
	if purpose == "contact-form" {
		return fmt.Sprintf("%d.%s.%s", issued, nonce, hex.EncodeToString(mac.Sum(nil))), nil
	}
	return fmt.Sprintf("%d.%s.%s.%s", issued, nonce, flags, hex.EncodeToString(mac.Sum(nil))), nil
}

func (s *Server) consumeContactToken(ctx context.Context, purpose, token string, fields contactFields, minAge, maxAge int, now time.Time) (string, bool) {
	parts := strings.Split(token, ".")
	if (purpose == "contact-form" && len(parts) != 3) || (purpose != "contact-form" && len(parts) != 4) {
		return "", false
	}
	issued, err := time.ParseDuration(parts[0] + "s")
	if err != nil {
		return "", false
	}
	stamp := int64(issued / time.Second)
	age := now.Unix() - stamp
	if age < int64(minAge) || age > int64(maxAge) {
		return "", false
	}
	secrets, err := s.contactSecrets(ctx)
	if err != nil {
		return "", false
	}
	bodyHash := ""
	if fields != nil {
		sum := sha256.Sum256([]byte(normalizedContactFields(fields)))
		bodyHash = hex.EncodeToString(sum[:])
	}
	flags := ""
	sigPart := parts[2]
	message := fmt.Sprintf("contact-form|%d|%s", stamp, parts[1])
	if purpose != "contact-form" {
		flags = parts[2]
		sigPart = parts[3]
		message = fmt.Sprintf("contact-review|%d|%s|%s|%s", stamp, parts[1], flags, bodyHash)
	}
	sig, err := hex.DecodeString(sigPart)
	if err != nil {
		return "", false
	}
	valid := 0
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(message))
		valid |= subtle.ConstantTimeCompare(sig, mac.Sum(nil))
	}
	if valid != 1 {
		return "", false
	}
	contactTokenState.Lock()
	defer contactTokenState.Unlock()
	for key, expiry := range contactTokenState.used {
		if !now.Before(expiry) {
			delete(contactTokenState.used, key)
		}
	}
	if _, exists := contactTokenState.used[purpose+":"+parts[1]]; exists {
		return flags, false
	}
	if len(contactTokenState.used) >= 50000 {
		for key := range contactTokenState.used {
			delete(contactTokenState.used, key)
			break
		}
	}
	contactTokenState.used[purpose+":"+parts[1]] = now.Add(time.Duration(maxAge) * time.Second)
	return flags, true
}

func normalizedContactFields(fields contactFields) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if key != "form_token" && key != "review_token" && key != "captcha_answer" && key != "captcha_id" && key != "website" && key != "step" && key != "confirmed" && key != "csrf_token" && key != "captcha_response" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		value := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(fields[key])), " "))
		fmt.Fprintf(&b, "%s=%s\n", key, value)
	}
	return b.String()
}

func readContactFields(r *http.Request) (contactFields, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, contactBodyLimit)
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	fields := contactFields{}
	if strings.Contains(contentType, "application/json") {
		decoder := json.NewDecoder(io.LimitReader(r.Body, contactBodyLimit+1))
		decoder.DisallowUnknownFields()
		var values map[string]json.RawMessage
		if err := decoder.Decode(&values); err != nil {
			return nil, err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("invalid trailing JSON")
		}
		for key, raw := range values {
			var value string
			if key == "confirmed" || key == "cve_requested" || key == "coordinated_agreement" {
				if err := json.Unmarshal(raw, &value); err != nil {
					var boolean bool
					if err = json.Unmarshal(raw, &boolean); err != nil {
						return nil, err
					}
					if boolean {
						value = "true"
					}
				}
				fields[key] = value
				continue
			}
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, err
			}
			fields[key] = value
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		for key, values := range r.PostForm {
			if len(values) > 1 {
				return nil, fmt.Errorf("repeated field")
			}
			if len(values) == 1 {
				fields[key] = values[0]
			}
		}
	}
	allowed := map[string]bool{"csrf_token": true, "name": true, "email": true, "type": true, "subject": true, "message": true, "reported_url": true, "reason": true, "copyrighted_work": true, "good_faith": true, "accurate": true, "signature": true, "request_kind": true, "step": true, "form_token": true, "review_token": true, "confirmed": true, "captcha_id": true, "captcha_answer": true, "captcha_response": true, "g-recaptcha-response": true, "h-captcha-response": true, "website": true, "security_id": true, "researcher_gpg": true, "component": true, "endpoint": true, "severity": true, "summary": true, "steps": true, "impact": true, "suggested_fix": true, "cve_requested": true, "disclosure_timeline_preference": true, "credit_preference": true, "credit_handle": true, "coordinated_disclosure_agreement": true}
	for key := range fields {
		if !allowed[key] {
			return nil, fmt.Errorf("unknown field")
		}
	}
	for _, v := range fields {
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("invalid UTF-8")
		}
		if strings.ContainsAny(v, "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069\u200b\u200c\u200d\ufeff") {
			return nil, fmt.Errorf("invalid characters")
		}
	}
	return fields, nil
}

func (s *Server) contactOriginOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	fetch := r.Header.Get("Sec-Fetch-Site")
	if fetch != "" && fetch != "same-origin" {
		return false
	}
	if origin == "" && referer == "" && fetch == "" {
		return false
	}
	_, host, _ := s.GetURLVars(r)
	own := strings.ToLower(host)
	check := origin
	if check == "" {
		check = referer
	}
	parsed, err := url.Parse(check)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, own) && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

func (s *Server) validateContactFields(fields contactFields, securityMode bool) string {
	for _, name := range []string{"name", "email"} {
		if strings.TrimSpace(fields[name]) == "" {
			return name
		}
		if len([]rune(strings.TrimSpace(fields[name]))) > 255 {
			return name
		}
		if strings.ContainsAny(fields[name], "\r\n\x00") {
			return name
		}
	}
	if !contactEmailPattern.MatchString(strings.TrimSpace(fields["email"])) {
		return "email"
	}
	parsed, err := mail.ParseAddress(fields["email"])
	if err != nil || parsed.Address != strings.TrimSpace(fields["email"]) {
		return "email"
	}
	if securityMode {
		limits := map[string]int{"component": 255, "endpoint": 2048, "severity": 32, "summary": 200, "steps": 10000, "impact": 5000, "suggested_fix": 5000, "researcher_gpg": 16384, "credit_handle": 100}
		for key, max := range limits {
			if len([]rune(strings.TrimSpace(fields[key]))) > max {
				return key
			}
		}
		if strings.HasPrefix(fields["researcher_gpg"], "https://") && len([]rune(fields["researcher_gpg"])) > 2048 {
			return "researcher_gpg"
		}
		if fields["researcher_gpg"] != "" && !strings.HasPrefix(fields["researcher_gpg"], "https://") && !strings.HasPrefix(fields["researcher_gpg"], "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
			return "researcher_gpg"
		}
		for _, key := range []string{"component", "severity", "summary", "steps", "impact", "credit_preference"} {
			if strings.TrimSpace(fields[key]) == "" {
				return key
			}
		}
		if strings.ContainsAny(fields["summary"], "\r\n\x00") {
			return "summary"
		}
		switch fields["severity"] {
		case "critical", "high", "medium", "low", "informational":
		default:
			return "severity"
		}
		switch fields["credit_preference"] {
		case "name", "handle", "no", "anon", "anonymous":
		default:
			return "credit_preference"
		}
		if fields["credit_preference"] == "handle" && strings.TrimSpace(fields["credit_handle"]) == "" {
			return "credit_handle"
		}
		if fields["coordinated_disclosure_agreement"] != "true" {
			return "coordinated_disclosure_agreement"
		}
		return ""
	}
	if fields["type"] != "abuse" && fields["type"] != "dmca" && fields["type"] != "privacy" {
		return "type"
	}
	allowed := map[string]bool{"name": true, "email": true, "type": true, "subject": true, "message": true, "reported_url": true, "reason": true, "copyrighted_work": true, "good_faith": true, "accurate": true, "signature": true, "request_kind": true, "step": true, "form_token": true, "review_token": true, "confirmed": true, "captcha_id": true, "captcha_answer": true, "captcha_response": true, "g-recaptcha-response": true, "h-captcha-response": true, "website": true, "security_id": true, "csrf_token": true}
	for key := range fields {
		if !allowed[key] {
			return key
		}
	}
	for _, key := range []string{"subject", "message"} {
		if strings.TrimSpace(fields[key]) == "" {
			return key
		}
		if len([]rune(fields[key])) > 10000 {
			return key
		}
		if strings.ContainsAny(fields[key], "\r\n\x00") && key == "subject" {
			return key
		}
	}
	if (fields["type"] == "abuse" || fields["type"] == "dmca") && strings.TrimSpace(fields["reported_url"]) == "" {
		return "reported_url"
	}
	if fields["type"] == "abuse" {
		switch fields["reason"] {
		case "illegal_content", "terms_violation", "harassment", "malware_phishing", "other":
		default:
			return "reason"
		}
	}
	if fields["type"] == "dmca" && (fields["good_faith"] != "true" || fields["accurate"] != "true" || strings.TrimSpace(fields["signature"]) == "") {
		return "signature"
	}
	if fields["type"] == "dmca" && strings.TrimSpace(fields["copyrighted_work"]) == "" {
		return "copyrighted_work"
	}
	if fields["type"] == "privacy" {
		switch fields["request_kind"] {
		case "access", "export", "deletion", "correction", "opt_out", "other":
		default:
			return "request_kind"
		}
	}
	return ""
}

func (s *Server) contactCaptcha(ctx context.Context, fields contactFields) bool {
	provider := strings.ToLower(strings.TrimSpace(s.config.Pages.Contact.Captcha))
	response := fields["captcha_response"]
	if response == "" {
		response = fields["g-recaptcha-response"]
	}
	if response == "" {
		response = fields["h-captcha-response"]
	}
	if provider != "" && provider != "simple" && response != "" {
		return s.verifyContactProviderCaptcha(ctx, provider, response)
	}
	id, answer := fields["captcha_id"], strings.TrimSpace(fields["captcha_answer"])
	if id == "" || answer == "" || s.database == nil {
		return false
	}
	var expected string
	err := s.database.Write(ctx, func(tx *sql.Tx) error {
		var hash string
		if err := tx.QueryRowContext(ctx, "SELECT answer_hash FROM captcha_challenges WHERE id=? AND expires_at>?", id, time.Now().Unix()).Scan(&hash); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(security.HashToken(answer)), []byte(hash)) != 1 {
			return fmt.Errorf("incorrect challenge")
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM captcha_challenges WHERE id=?", id)
		expected = hash
		return err
	})
	return err == nil && expected != ""
}

func (s *Server) verifyContactProviderCaptcha(ctx context.Context, provider, token string) bool {
	endpoint := ""
	switch provider {
	case "recaptcha":
		endpoint = "https://www.google.com/recaptcha/api/siteverify"
	case "hcaptcha":
		endpoint = "https://api.hcaptcha.com/siteverify"
	default:
		return false
	}
	secret := s.config.Pages.Contact.CaptchaSecretKey
	if secret == "" || token == "" {
		return false
	}
	form := url.Values{"secret": {secret}, "response": {token}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return false
	}
	var result struct{ Success bool }
	if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result) != nil {
		return false
	}
	return result.Success
}

func (s *Server) newContactCaptcha(ctx context.Context) (map[string]string, error) {
	if s.database == nil {
		return nil, fmt.Errorf("challenge storage unavailable")
	}
	_ = s.database.ExecWrite(ctx, "DELETE FROM captcha_challenges WHERE id IN (SELECT id FROM captcha_challenges WHERE expires_at<=? LIMIT 500)", time.Now().Unix())
	raw := make([]byte, 2)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	a, b := int(raw[0])%20+1, int(raw[1])%20+1
	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idRaw)
	err := s.database.ExecWrite(ctx, "INSERT INTO captcha_challenges(id,answer_hash,expires_at) VALUES(?,?,?)", id, security.HashToken(fmt.Sprint(a+b)), time.Now().Add(10*time.Minute).Unix())
	if err != nil {
		return nil, err
	}
	return map[string]string{"provider": "simple", "captcha_id": id, "question": fmt.Sprintf("%d + %d = ?", a, b)}, nil
}

func contactSecurityMode(s *Server, r *http.Request, fields contactFields) bool {
	id := r.URL.Query().Get("security_id")
	if id == "" {
		id = fields["security_id"]
	}
	return id != "" && s.validSecurityID(r.Context(), id, time.Now())
}

func (s *Server) logContactBlock(reason string, r *http.Request) {
	if s.logger != nil {
		s.logger.WriteSecurity(fmt.Sprintf("contact.spam_blocked reason=%q ip=%q", reason, extractClientIP(r, s.config.TrustedProxies.Additional)))
	}
	if s.metrics != nil && s.metrics.ContactBlockedTotal != nil {
		s.metrics.ContactBlockedTotal.WithLabelValues(reason).Inc()
	}
}

func (s *Server) deliverContact(fields contactFields) error {
	recipient := s.config.Contact.General.Email
	if fields["type"] == "abuse" || fields["type"] == "dmca" {
		recipient = s.config.Contact.Abuse.Email
		if recipient == "" {
			recipient = s.config.Contact.General.Email
		}
	}
	if fields["type"] == "privacy" {
		recipient = s.config.Contact.DPO.Email
		if recipient == "" {
			recipient = s.config.Contact.General.Email
		}
	}
	if recipient == "" {
		recipient = s.config.Contact.Admin.Email
	}
	if recipient == "" || s.email == nil || !s.email.IsEnabled() {
		return fmt.Errorf("contact delivery is unavailable")
	}
	appName := s.config.Branding.Title
	if appName == "" {
		appName = "Whois"
	}
	return s.email.SendEmailWithReplyTo(recipient, strings.TrimSpace(fields["email"]), "contact", map[string]string{"subject": "[" + appName + " contact] " + fields["subject"], "app_name": appName, "fqdn": s.config.FQDN, "sender_name": strings.TrimSpace(fields["name"]), "sender_email": strings.TrimSpace(fields["email"]), "message": strings.TrimSpace(fields["message"]), "type": fields["type"], "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

var contactAccepted = struct {
	sync.Mutex
	events map[string][]time.Time
}{events: map[string][]time.Time{}}
var contactStrikes = struct {
	sync.Mutex
	events map[string][]time.Time
	banned map[string]time.Time
}{events: map[string][]time.Time{}, banned: map[string]time.Time{}}

func (s *Server) contactIP(r *http.Request) string {
	_, host, _ := s.GetURLVars(r)
	if strings.HasSuffix(strings.ToLower(host), ".onion") || strings.HasSuffix(strings.ToLower(host), ".i2p") {
		return ""
	}
	return extractClientIP(r, s.config.TrustedProxies.Additional)
}
func contactIPBanned(ip string) bool {
	if ip == "" {
		return false
	}
	now := time.Now()
	contactStrikes.Lock()
	defer contactStrikes.Unlock()
	until := contactStrikes.banned[ip]
	if until.After(now) {
		return true
	}
	delete(contactStrikes.banned, ip)
	return false
}
func (s *Server) addContactStrike(reason, ip string) {
	if ip == "" {
		return
	}
	switch reason {
	case "honeypot", "captcha", "content", "markup", "duplicate", "origin", "replay":
	default:
		return
	}
	now := time.Now()
	contactStrikes.Lock()
	defer contactStrikes.Unlock()
	events := contactStrikes.events[ip]
	kept := events[:0]
	for _, at := range events {
		if now.Sub(at) < time.Hour {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	contactStrikes.events[ip] = kept
	if len(kept) >= 3 {
		contactStrikes.banned[ip] = now.Add(24 * time.Hour)
		delete(contactStrikes.events, ip)
	}
}

func (s *Server) checkContactRate(ip, email string, count bool) string {
	now := time.Now()
	window := time.Hour
	if configured, err := time.ParseDuration(s.config.Pages.Contact.Antispam.Window); err == nil && configured > 0 {
		window = configured
	}
	contactAccepted.Lock()
	defer contactAccepted.Unlock()
	for key, items := range contactAccepted.events {
		kept := items[:0]
		for _, at := range items {
			if now.Sub(at) < window {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(contactAccepted.events, key)
		} else {
			contactAccepted.events[key] = kept
		}
	}
	limits := []struct {
		key, reason string
		limit       int
	}{{"email:" + strings.ToLower(email), "rate_email", s.config.Pages.Contact.Antispam.PerEmail}, {"global", "rate_global", s.config.Pages.Contact.Antispam.Global}}
	if ip != "" {
		limits = append([]struct {
			key, reason string
			limit       int
		}{{"ip:" + ip, "rate_ip", s.config.Pages.Contact.Antispam.PerIP}}, limits...)
	}
	for _, item := range limits {
		if item.limit > 0 && len(contactAccepted.events[item.key]) >= item.limit {
			return item.reason
		}
	}
	if count {
		for _, item := range limits {
			contactAccepted.events[item.key] = append(contactAccepted.events[item.key], now)
		}
	}
	return ""
}

func (s *Server) contactBlockResponse(w http.ResponseWriter, r *http.Request, isAPI bool, reason, message string, status int) {
	s.addContactStrike(reason, s.contactIP(r))
	s.logContactBlock(reason, r)
	if isAPI {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "3600")
		}
		if message == "" {
			message = "Your message could not be sent"
		}
		SendError(w, ErrValidationFailed, message)
		return
	}
	s.renderContactForm(w, r, contactFields{}, false, "", message)
}

func (s *Server) handleContactFlow(w http.ResponseWriter, r *http.Request, isAPI bool) {
	if !s.config.Pages.Contact.Enabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeRequestError(w, r, http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		if isAPI {
			fields := []map[string]any{{"name": "name", "type": "text", "required": true, "max_length": 255}, {"name": "email", "type": "email", "required": true, "max_length": 255}, {"name": "type", "type": "select", "required": true, "max_length": nil}, {"name": "subject", "type": "text", "required": true, "max_length": 200}, {"name": "message", "type": "textarea", "required": true, "max_length": 10000}, {"name": "reported_url", "type": "url", "required": false, "required_when": map[string]any{"field": "type", "in": []string{"abuse", "dmca"}}, "max_length": 2048}, {"name": "good_faith", "type": "checkbox", "required": false, "max_length": nil}, {"name": "accurate", "type": "checkbox", "required": false, "max_length": nil}, {"name": "signature", "type": "text", "required": false, "max_length": 100}, {"name": "researcher_gpg", "type": "text", "required": false, "max_length": 16384, "max_length_when": []map[string]any{{"prefix": "https://", "max_length": 2048}}}, {"name": "component", "type": "text", "required": true, "max_length": 255}, {"name": "endpoint", "type": "text", "required": false, "max_length": 2048}, {"name": "severity", "type": "select", "required": true, "max_length": nil}, {"name": "summary", "type": "text", "required": true, "max_length": 200}, {"name": "steps", "type": "textarea", "required": true, "max_length": 10000}, {"name": "impact", "type": "textarea", "required": true, "max_length": 5000}, {"name": "suggested_fix", "type": "textarea", "required": false, "max_length": 5000}, {"name": "cve_requested", "type": "checkbox", "required": false, "max_length": nil}, {"name": "disclosure_timeline_preference", "type": "number", "required": false, "max_length": nil}, {"name": "credit_preference", "type": "select", "required": true, "max_length": nil}, {"name": "credit_handle", "type": "text", "required": false, "max_length": 100, "required_when": map[string]any{"field": "credit_preference", "equals": "handle"}}, {"name": "coordinated_disclosure_agreement", "type": "checkbox", "required": true, "max_length": nil}}
			fields = append(fields, map[string]any{"name": "reason", "type": "select", "required": false, "required_when": map[string]any{"field": "type", "equals": "abuse"}, "max_length": nil}, map[string]any{"name": "copyrighted_work", "type": "textarea", "required": false, "required_when": map[string]any{"field": "type", "equals": "dmca"}, "max_length": 2000}, map[string]any{"name": "request_kind", "type": "select", "required": false, "required_when": map[string]any{"field": "type", "equals": "privacy"}, "max_length": nil})
			captcha, err := s.newContactCaptcha(r.Context())
			if err != nil {
				SendError(w, ErrServerError, "Unable to create challenge")
				return
			}
			token, err := s.issueContactToken(r.Context(), "contact-form", nil, "", time.Now())
			if err != nil {
				SendError(w, ErrServerError, "Unable to initialize form")
				return
			}
			provider := s.config.Pages.Contact.Captcha
			if provider == "" {
				provider = "simple"
			}
			captchaDescriptor := map[string]any{"provider": "simple", "captcha_id": captcha["captcha_id"], "question": captcha["question"]}
			if provider != "simple" {
				captchaDescriptor = map[string]any{"provider": provider, "site_key": s.config.Pages.Contact.CaptchaSiteKey, "fallback": map[string]any{"provider": "simple", "captcha_id": captcha["captcha_id"], "question": captcha["question"]}}
			}
			securityURL := s.securityReportURL(r.Context(), r, time.Now())
			abuse := s.config.Contact.Abuse.Email
			if abuse == "" {
				abuse = s.config.Contact.General.Email
			}
			types := []string{"abuse", "dmca", "privacy"}
			if contactSecurityMode(s, r, nil) {
				types = append(types, "security")
			}
			data := map[string]any{"fields": fields, "captcha": captchaDescriptor, "form_token": token, "types": types, "security_url": securityURL, "abuse_email": abuse}
			if contactSecurityMode(s, r, nil) {
				data["security_id"] = r.URL.Query().Get("security_id")
			}
			SendSuccess(w, data)
			return
		}
		if contactSecurityMode(s, r, nil) {
			s.renderContactForm(w, r, contactFields{"security_id": r.URL.Query().Get("security_id")}, false, "", "")
			return
		}
		typ := r.URL.Query().Get("type")
		if typ != "abuse" && typ != "dmca" && typ != "privacy" {
			s.renderContactChooser(w, r)
			return
		}
		s.renderContactForm(w, r, contactFields{"type": typ}, false, "", "")
		return
	}
	ip := s.contactIP(r)
	if contactIPBanned(ip) {
		s.contactBlockResponse(w, r, isAPI, "banned", "Too many requests", http.StatusTooManyRequests)
		return
	}
	if !isAPI && !s.contactOriginOK(r) {
		s.contactBlockResponse(w, r, false, "origin", "Please submit the form from this site", http.StatusBadRequest)
		return
	}
	fields, err := readContactFields(r)
	if err != nil {
		s.contactBlockResponse(w, r, isAPI, "shape", "Invalid form submission", http.StatusBadRequest)
		return
	}
	if len(fields) > 35 {
		s.contactBlockResponse(w, r, isAPI, "shape", "Invalid form submission", http.StatusBadRequest)
		return
	}
	if fields["step"] == "edit" {
		if isAPI {
			SendSuccess(w, map[string]any{"edit": true})
			return
		}
		s.renderContactForm(w, r, fields, false, "", "")
		return
	}
	if fields["security_id"] == "" {
		fields["security_id"] = r.URL.Query().Get("security_id")
	}
	securityMode := contactSecurityMode(s, r, fields)
	if !securityMode {
		s.logInvalidSecurityIDIfPresent(r)
	}
	fieldError := s.validateContactFields(fields, securityMode)
	if fieldError != "" {
		s.contactBlockResponse(w, r, isAPI, "shape", "VALIDATION_FAILED: "+fieldError, http.StatusBadRequest)
		return
	}
	flags := ""
	if fields["step"] == "confirm" {
		var ok bool
		flags, ok = s.consumeContactToken(r.Context(), "contact-review", fields["review_token"], fields, 2, 900, time.Now())
		if !ok {
			s.contactBlockResponse(w, r, isAPI, "review", "Please read the details and confirm", http.StatusBadRequest)
			return
		}
	} else {
		if fields["form_token"] == "" {
			s.contactBlockResponse(w, r, isAPI, "fill_time", "Please wait a moment and submit again", http.StatusBadRequest)
			return
		}
		_, ok := s.consumeContactToken(r.Context(), "contact-form", fields["form_token"], nil, s.config.Pages.Contact.Antispam.MinFillSeconds, s.config.Pages.Contact.Antispam.MaxAgeSeconds, time.Now())
		if !ok {
			s.contactBlockResponse(w, r, isAPI, "fill_time", "Please wait a moment and submit again", http.StatusBadRequest)
			return
		}
	}
	if fields["step"] != "confirm" {
		if fields["website"] != "" {
			flags = "d"
			s.addContactStrike("honeypot", ip)
			s.logContactBlock("honeypot", r)
		}
		if !s.contactCaptcha(r.Context(), fields) {
			s.contactBlockResponse(w, r, isAPI, "captcha", "Please complete the challenge", http.StatusBadRequest)
			return
		}
		if !securityMode {
			if reason := s.contactContentFailure(fields); reason != "" {
				s.contactBlockResponse(w, r, isAPI, reason, "Your message could not be sent", http.StatusBadRequest)
				return
			}
		}
		token, err := s.issueContactToken(r.Context(), "contact-review", fields, flags, time.Now())
		if err != nil {
			SendError(w, ErrServerError, "Unable to continue form")
			return
		}
		if isAPI {
			reviewType, subject := fields["type"], fields["subject"]
			if securityMode {
				reviewType, subject = "security", fields["summary"]
			}
			SendSuccess(w, map[string]any{"review": map[string]string{"type": reviewType, "email": fields["email"], "subject": subject}, "review_token": token, "confirm_after_seconds": 2})
			return
		}
		fields["review_token"] = token
		s.renderContactForm(w, r, fields, true, "", "")
		return
	}
	if fields["confirmed"] != "true" {
		s.contactBlockResponse(w, r, isAPI, "review", "Please read the details and confirm", http.StatusBadRequest)
		return
	}
	contactIP := s.contactIP(r)
	if reason := s.checkContactRate(contactIP, fields["email"], true); reason != "" {
		s.contactBlockResponse(w, r, isAPI, reason, "Too many submissions", http.StatusTooManyRequests)
		return
	}
	if flags == "d" || fields["website"] != "" {
		if isAPI {
			SendSuccess(w, map[string]string{"message": "Thank you"})
		} else {
			s.renderContactForm(w, r, nil, false, "Thank you for your message.", "")
		}
		return
	}
	if securityMode {
		input := securityReportInput{Name: fields["name"], Email: fields["email"], ResearcherGPG: fields["researcher_gpg"], Component: fields["component"], Endpoint: fields["endpoint"], Severity: fields["severity"], Summary: fields["summary"], Steps: fields["steps"], Impact: fields["impact"], SuggestedFix: fields["suggested_fix"], Timeline: fields["disclosure_timeline_preference"], CreditPreference: fields["credit_preference"], CreditHandle: fields["credit_handle"], CVERequested: fields["cve_requested"] == "true", CoordinatedAgreement: fields["coordinated_disclosure_agreement"] == "true", AppVersion: Version, CommitHash: CommitID, Timestamp: time.Now().UTC().Format(time.RFC3339), UserAgent: r.UserAgent()}
		var researcherKey []byte
		if input.ResearcherGPG != "" {
			var keyErr error
			researcherKey, keyErr = loadResearcherPGPKey(r.Context(), input.ResearcherGPG)
			if keyErr != nil {
				s.contactBlockResponse(w, r, isAPI, "researcher_key", "The supplied PGP key could not be validated", http.StatusBadRequest)
				return
			}
			input.ResearcherGPG = string(researcherKey)
		}
		tracking, token, err := s.storeSecurityReport(r.Context(), r, fields["security_id"], input)
		if err != nil {
			SendError(w, ErrServerError, "Unable to store security report")
			return
		}
		statusURL := s.BuildURL(r, "/server/security/report/"+tracking) + "?token=" + url.QueryEscape(token)
		notified := false
		securityRecipient := s.config.Contact.Security.Email
		if securityRecipient == "" {
			securityRecipient = s.config.Contact.Admin.Email
		}
		if s.email != nil && s.email.IsEnabled() && securityRecipient != "" {
			var encrypted []byte
			var algorithm string
			if err := s.database.Read().QueryRowContext(r.Context(), "SELECT body_enc,body_alg FROM security_reports WHERE tracking_id=?", tracking).Scan(&encrypted, &algorithm); err != nil || len(encrypted) == 0 {
				if s.logger != nil {
					s.logger.WriteSecurity(fmt.Sprintf("security.report_notification_failed tracking_id=%q reason=%q", tracking, "encrypted report unavailable"))
				}
			} else {
				notification := map[string]string{"app_name": s.config.Branding.Title, "fqdn": s.config.FQDN, "timestamp": time.Now().UTC().Format(time.RFC3339), "event": "Coordinated disclosure report received", "ip": "redacted", "details": string(encrypted)}
				var notificationErr error
				switch algorithm {
				case "aes-256-gcm":
					notification["details"] = "WARNING: No project PGP key is configured. The report is attached as AES-256-GCM ciphertext, not plaintext."
					notificationErr = s.email.SendEmailWithAttachment(securityRecipient, "security_alert", notification, email.EmailAttachment{Filename: tracking + ".enc", ContentType: "application/octet-stream", Content: encrypted})
				case "pgp":
					notificationErr = s.email.SendEmail(securityRecipient, "security_alert", notification)
				default:
					notificationErr = fmt.Errorf("unsupported report encryption algorithm")
				}
				if notificationErr == nil {
					notified = true
				} else if s.logger != nil {
					s.logger.WriteSecurity(fmt.Sprintf("security.report_notification_failed tracking_id=%q reason=%q", tracking, "encrypted notification delivery failed"))
				}
			}
		}
		message := "We received your report. Your tracking ID is " + tracking + "."
		if s.email != nil && s.email.IsEnabled() {
			details := "Tracking ID: " + tracking + "\nStatus: " + statusURL
			if len(researcherKey) > 0 {
				detailsBytes, encryptErr := security.EncryptPGP(researcherKey, []byte(details))
				if encryptErr != nil {
					details = ""
				} else {
					details = string(detailsBytes)
				}
			}
			if details != "" {
				if err := s.email.SendEmail(fields["email"], "security_alert", map[string]string{"app_name": s.config.Branding.Title, "fqdn": s.config.FQDN, "timestamp": time.Now().UTC().Format(time.RFC3339), "event": "Your report tracking details", "ip": "redacted", "details": details}); err == nil {
					message += " A confirmation email is on its way."
				}
			}
		}
		if s.logger != nil {
			s.logger.WriteSecurity(fmt.Sprintf("security.report_received tracking_id=%q notified=%t severity=%q component=%q", tracking, notified, fields["severity"], sanitizeLogField(fields["component"])))
		}
		if isAPI {
			SendSuccess(w, map[string]string{"tracking_id": tracking, "message": message})
		} else {
			s.renderContactForm(w, r, nil, false, message, "")
		}
		return
	}
	if reason := s.contactCheckDuplicate(fields); reason {
		s.addContactStrike("duplicate", s.contactIP(r))
		s.logContactBlock("duplicate", r)
		if isAPI {
			SendSuccess(w, map[string]string{"message": "Thank you"})
		} else {
			s.renderContactForm(w, r, nil, false, "Thank you for your message.", "")
		}
		return
	}
	if err := s.deliverContact(fields); err != nil {
		SendError(w, ErrServerError, "Unable to deliver contact message")
		return
	}
	message := s.config.Pages.Contact.SuccessMessage
	if message == "" {
		message = "Thank you for your message. We'll respond soon."
	}
	if isAPI {
		SendSuccess(w, map[string]string{"message": message})
	} else {
		s.renderContactForm(w, r, nil, false, message, "")
	}
}

func (s *Server) renderContactForm(w http.ResponseWriter, r *http.Request, values contactFields, review bool, success, problem string) {
	if values == nil {
		values = contactFields{}
	}
	if values["security_id"] == "" {
		values["security_id"] = r.URL.Query().Get("security_id")
	}
	formToken, _ := s.issueContactToken(r.Context(), "contact-form", nil, "", time.Now())
	captcha, _ := s.newContactCaptcha(r.Context())
	name := s.config.Branding.Title
	if name == "" {
		name = "Whois"
	}
	captchaType := s.config.Pages.Contact.Captcha
	if captchaType == "" {
		captchaType = "simple"
	}
	abuse := s.config.Contact.Abuse.Email
	if abuse == "" {
		abuse = s.config.Contact.General.Email
	}
	data := ContactPageData{translatablePageData: s.newPageData(w, r), Name: name, Enabled: true, Captcha: captchaType, SuccessMessage: success, Submitted: success != "", AbuseEmail: abuse, FormToken: formToken, CaptchaID: captcha["captcha_id"], CaptchaQuestion: captcha["question"], Review: review, ReviewToken: values["review_token"], SecurityMode: contactSecurityMode(s, r, values), Values: values, ErrorMessage: problem, Step: "submit", Type: values["type"], FQDN: s.config.FQDN}
	if review {
		data.Step = "confirm"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(contactTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) renderContactChooser(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = "Whois"
	}
	abuse := s.config.Contact.Abuse.Email
	if abuse == "" {
		abuse = s.config.Contact.General.Email
	}
	data := ContactPageData{translatablePageData: s.newPageData(w, r), Name: name, Enabled: true, Chooser: true, AbuseEmail: abuse}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(contactTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) contactContentFailure(fields contactFields) string {
	cfg := s.config.Pages.Contact.Antispam
	for key, value := range fields {
		if cfg.RejectMarkup {
			lower := strings.ToLower(value)
			if strings.Contains(lower, "<") || strings.Contains(lower, "&#") || strings.Contains(lower, "[url") || strings.Contains(lower, "[img") || strings.Contains(lower, "[b]") {
				return "markup"
			}
		}
		for _, word := range cfg.BlockedWords {
			if word != "" && strings.Contains(strings.ToLower(value), strings.ToLower(word)) {
				return "content"
			}
		}
		if key == "name" || key == "subject" {
			if contactLinkCount(value) > 0 {
				return "content"
			}
		}
	}
	emailParts := strings.Split(strings.ToLower(fields["email"]), "@")
	if len(emailParts) == 2 {
		for _, domain := range cfg.BlockedEmailDomains {
			if strings.EqualFold(strings.TrimSpace(domain), emailParts[1]) {
				return "content"
			}
		}
	}
	links := 0
	for key, value := range fields {
		if key != "message" && key != "reason" && key != "copyrighted_work" {
			continue
		}
		for _, host := range contactLinkHosts(value) {
			links++
			if !s.allowedContactHost(host) {
				return "content"
			}
		}
	}
	if cfg.MaxLinks > 0 && links > cfg.MaxLinks {
		return "content"
	}
	if fields["type"] == "abuse" || fields["type"] == "dmca" {
		if !s.reportedURLMatches(fields["reported_url"]) {
			return "content"
		}
	}
	return ""
}

var contactDuplicates = struct {
	sync.Mutex
	seen map[string]time.Time
}{seen: map[string]time.Time{}}

func (s *Server) contactCheckDuplicate(fields contactFields) bool {
	value := strings.ToLower(strings.Join([]string{strings.TrimSpace(fields["email"]), strings.TrimSpace(fields["subject"]), strings.TrimSpace(fields["message"])}, "\n"))
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(value), " ")))
	key := hex.EncodeToString(sum[:])
	now := time.Now()
	contactDuplicates.Lock()
	defer contactDuplicates.Unlock()
	for k, at := range contactDuplicates.seen {
		if now.Sub(at) > 24*time.Hour {
			delete(contactDuplicates.seen, k)
		}
	}
	if _, ok := contactDuplicates.seen[key]; ok {
		return true
	}
	if len(contactDuplicates.seen) >= 10000 {
		for k := range contactDuplicates.seen {
			delete(contactDuplicates.seen, k)
			break
		}
	}
	contactDuplicates.seen[key] = now
	return false
}

var contactURLPattern = regexp.MustCompile(`(?i)(?:https?://|www\.)[^\s<>()]+|\b[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>()]*)?`)

func contactLinkHosts(value string) []string {
	value = contactEmailPattern.ReplaceAllStringFunc(value, func(string) string { return " " })
	matches := contactURLPattern.FindAllString(value, -1)
	hosts := make([]string, 0, len(matches))
	for _, match := range matches {
		if strings.Contains(match, "@") && !strings.Contains(match, "://") {
			continue
		}
		raw := match
		if strings.HasPrefix(strings.ToLower(raw), "www.") {
			raw = "https://" + raw
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, strings.ToLower(parsed.Hostname()))
		}
	}
	return hosts
}
func contactLinkCount(value string) int { return len(contactLinkHosts(value)) }
func (s *Server) allowedContactHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.EqualFold(host, s.config.FQDN) || host == "localhost" {
		return true
	}
	if torService := s.currentTor(); torService != nil {
		torHost := strings.ToLower(strings.TrimSuffix(torService.OnionAddress(), "."))
		if host == torHost {
			return true
		}
	}
	if overlay := s.currentI2P(); overlay != nil {
		i2pHost := strings.ToLower(strings.TrimSuffix(overlay.Address(), "."))
		if host == i2pHost {
			return true
		}
	}
	for _, entry := range strings.Split(strings.TrimSpace(os.Getenv("DOMAIN")), ",") {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(entry), "."), host) {
			return true
		}
	}
	return false
}
func (s *Server) reportedURLMatches(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if path == "/" || strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/server/contact") || strings.HasPrefix(path, "/contact") {
		return false
	}
	if parsed.IsAbs() && !s.allowedContactHost(parsed.Hostname()) {
		return false
	}
	known := map[string]bool{"/": true, "/about": true, "/docs": true, "/server/about": true, "/server/privacy": true, "/server/security": true, "/server/security/policy": true, "/server/security/thanks": true, "/server/help": true, "/server/terms": true, "/server/dpo": true}
	return known[path]
}
