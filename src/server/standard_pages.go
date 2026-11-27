package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/security"
)

// PrivacyPageData holds the dynamic data for the /server/privacy page
// (AI.md PART 16 — Standard Pages, /server/privacy).
type PrivacyPageData struct {
	translatablePageData
	Name                  string
	DataSold              bool
	StoredOnServer        bool
	Sharing               []SharingConditionView
	TrackingType          string
	TrackingTypeName      string
	AnalyticsDesc         string
	EssentialCookieDesc   string
	PreferencesCookieDesc string
	DataCollection        string
	DataUsage             string
	DataSecurity          string
	RetentionPeriod       string
	ExportAvailable       bool
	DeletionAvailable     bool
	ThirdPartyServices    []ThirdPartyServiceView
	CCPAApplicable        bool
	CCPAOptedOut          bool
}

// SharingConditionView is the display-ready form of a config.SharingCondition.
type SharingConditionView struct {
	Condition string
	When      string
	Data      string
}

// ThirdPartyServiceView is the display-ready form of a config.ThirdPartyService.
type ThirdPartyServiceView struct {
	Name      string
	Purpose   string
	DataSent  string
	PolicyURL string
}

var privacyTmpl = mustParseTemplate("privacy", "page/privacy.tmpl")

const privacyDataCollection = `**We collect only what is necessary to provide our service:**

**Usage Information (with consent):**
- Pages visited and features used
- Browser type and device information
- Approximate location (country/region from IP, not precise)

**Technical Information:**
- IP address (for security and abuse prevention)
- API token identifiers (hashed, never stored in plain text)

**We do NOT collect:**
- Payment information (unless explicitly required by the service)
- Precise location data
- Data from other websites or apps`

const privacyDataSecurityCommon = `**How we protect your data:**

- All data is stored on our servers (not third-party cloud services unless specified)
- API tokens are stored as SHA-256 hashes (never in plain text)
- Regular security audits and updates
- Access controls and audit logging for operator actions`

func privacyDataSecurity(s *Server, r *http.Request) string {
	securityText := privacyDataSecurityCommon
	proto := ""
	if r != nil {
		proto, _, _ = s.GetURLVars(r)
	}
	if proto == "https" {
		return strings.Replace(securityText, "- Regular security audits", "- Connections are encrypted with HTTPS/TLS\n- Regular security audits", 1)
	}
	return strings.Replace(securityText, "- Regular security audits", "- This site is currently served without TLS\n- Regular security audits", 1)
}

// handlePrivacyPage serves the privacy policy page.
// GET /server/privacy
func (s *Server) handlePrivacyPage(w http.ResponseWriter, r *http.Request) {
	p := s.config.Privacy
	sharing := make([]SharingConditionView, 0, len(p.Data.Sharing))
	for _, sc := range p.Data.Sharing {
		sharing = append(sharing, SharingConditionView{Condition: sc.Condition, When: sc.When, Data: sc.Data})
	}
	services := make([]ThirdPartyServiceView, 0, len(p.ThirdParty.Services))
	for _, svc := range p.ThirdParty.Services {
		services = append(services, ThirdPartyServiceView{Name: svc.Name, Purpose: svc.Purpose, DataSent: svc.DataSent, PolicyURL: svc.PolicyURL})
	}
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	dataUsage := p.GetDataUsageContent()
	if dataUsage == "" {
		dataUsage = "We use collected data solely to operate and improve the service."
	}
	data := PrivacyPageData{
		translatablePageData:  s.newPageData(w, r),
		Name:                  name,
		DataSold:              p.Data.Sold,
		StoredOnServer:        p.Data.StoredOnServer,
		Sharing:               sharing,
		TrackingType:          s.config.Tracking.Type,
		TrackingTypeName:      s.config.Tracking.TypeName(),
		AnalyticsDesc:         p.GetAnalyticsDescription(),
		EssentialCookieDesc:   p.Cookies.Essential.Description,
		PreferencesCookieDesc: p.Cookies.Preferences.Description,
		DataCollection:        privacyDataCollection,
		DataUsage:             dataUsage,
		DataSecurity:          privacyDataSecurity(s, r),
		RetentionPeriod:       p.Retention.Period,
		ExportAvailable:       p.Retention.ExportAvailable,
		DeletionAvailable:     p.Retention.DeletionAvailable,
		ThirdPartyServices:    services,
		CCPAApplicable:        p.IsCCPAApplicable(),
		CCPAOptedOut:          ccpaOptedOut(r),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(privacyTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// ccpaOptedOut reports whether the visitor has previously opted out via the
// ccpa_opt_out cookie (AI.md PART 16 — Cookie Consent Banner, CCPA Compliance).
func ccpaOptedOut(r *http.Request) bool {
	c, err := r.Cookie(ccpaCookieName)
	return err == nil && c.Value == "true"
}

// privacySharingJSON and privacyThirdPartyJSON are the JSON shapes for the
// /api/{api_version}/server/privacy response (AI.md PART 16 — /server/privacy,
// Privacy JSON Response format).
type privacySharingJSON struct {
	Condition string `json:"condition"`
	When      string `json:"when"`
	Data      string `json:"data"`
}

type privacyThirdPartyJSON struct {
	Name      string `json:"name"`
	Purpose   string `json:"purpose"`
	DataSent  string `json:"data_sent"`
	PolicyURL string `json:"policy_url"`
}

type privacyAPIResponse struct {
	Summary struct {
		DataStoredOnServer bool `json:"data_stored_on_server"`
		DataSold           bool `json:"data_sold"`
		UserControl        bool `json:"user_control"`
	} `json:"summary"`
	Cookies struct {
		Essential   privacyCookieJSON `json:"essential"`
		Preferences privacyCookieJSON `json:"preferences"`
		Analytics   privacyCookieJSON `json:"analytics"`
	} `json:"cookies"`
	Data struct {
		Sold           bool                 `json:"sold"`
		StoredOnServer bool                 `json:"stored_on_server"`
		Sharing        []privacySharingJSON `json:"sharing"`
	} `json:"data"`
	Tracking struct {
		Enabled  bool   `json:"enabled"`
		Type     string `json:"type"`
		TypeName string `json:"type_name"`
	} `json:"tracking"`
	Retention struct {
		Period            string `json:"period"`
		ExportAvailable   bool   `json:"export_available"`
		DeletionAvailable bool   `json:"deletion_available"`
	} `json:"retention"`
	ThirdParty struct {
		Services []privacyThirdPartyJSON `json:"services"`
	} `json:"third_party"`
	CCPA struct {
		Applicable   bool   `json:"applicable"`
		OptOutURL    string `json:"opt_out_url"`
		UserOptedOut bool   `json:"user_opted_out"`
	} `json:"ccpa"`
	Content struct {
		ConsentMessage string `json:"consent_message"`
		DataUsage      string `json:"data_usage"`
	} `json:"content"`
}

type privacyCookieJSON struct {
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// handlePrivacyAPI serves the privacy policy JSON response.
// GET /api/{api_version}/server/privacy
func (s *Server) handlePrivacyAPI(w http.ResponseWriter, r *http.Request) {
	p := s.config.Privacy
	var resp privacyAPIResponse
	resp.Summary.DataStoredOnServer = p.Data.StoredOnServer
	resp.Summary.DataSold = p.Data.Sold
	resp.Summary.UserControl = p.Retention.ExportAvailable || p.Retention.DeletionAvailable
	resp.Cookies.Essential = privacyCookieJSON{Enabled: p.Cookies.Essential.Enabled, Description: p.Cookies.Essential.Description}
	resp.Cookies.Preferences = privacyCookieJSON{Enabled: p.Cookies.Preferences.Enabled, Description: p.Cookies.Preferences.Description}
	resp.Cookies.Analytics = privacyCookieJSON{Enabled: p.Cookies.Analytics.Enabled, Description: p.GetAnalyticsDescription()}
	resp.Data.Sold = p.Data.Sold
	resp.Data.StoredOnServer = p.Data.StoredOnServer
	for _, sc := range p.Data.Sharing {
		resp.Data.Sharing = append(resp.Data.Sharing, privacySharingJSON{Condition: sc.Condition, When: sc.When, Data: sc.Data})
	}
	resp.Tracking.Enabled = s.config.Tracking.Type != ""
	resp.Tracking.Type = s.config.Tracking.Type
	resp.Tracking.TypeName = s.config.Tracking.TypeName()
	resp.Retention.Period = p.Retention.Period
	resp.Retention.ExportAvailable = p.Retention.ExportAvailable
	resp.Retention.DeletionAvailable = p.Retention.DeletionAvailable
	for _, svc := range p.ThirdParty.Services {
		resp.ThirdParty.Services = append(resp.ThirdParty.Services, privacyThirdPartyJSON{Name: svc.Name, Purpose: svc.Purpose, DataSent: svc.DataSent, PolicyURL: svc.PolicyURL})
	}
	resp.CCPA.Applicable = p.IsCCPAApplicable()
	resp.CCPA.OptOutURL = "/server/ccpa"
	resp.CCPA.UserOptedOut = ccpaOptedOut(r)
	resp.Content.ConsentMessage = p.GetConsentMessage()
	resp.Content.DataUsage = p.GetDataUsageContent()

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data_sold: " + boolStr(resp.Summary.DataSold) + "\n"))
		_, _ = w.Write([]byte("data_stored_on_server: " + boolStr(resp.Summary.DataStoredOnServer) + "\n"))
		_, _ = w.Write([]byte("ccpa_applicable: " + boolStr(resp.CCPA.Applicable) + "\n"))
		return
	}
	SendSuccess(w, resp)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ContactPageData holds the dynamic data for the /server/contact page.
type ContactPageData struct {
	translatablePageData
	Name            string
	Enabled         bool
	Captcha         string
	SuccessMessage  string
	Submitted       bool
	AbuseEmail      string
	FormToken       string
	ReviewToken     string
	CaptchaID       string
	CaptchaQuestion string
	Step            string
	Review          bool
	SecurityMode    bool
	Values          map[string]string
	ErrorMessage    string
	Chooser         bool
	Type            string
	FQDN            string
}

var contactTmpl = mustParseTemplate("contact", "page/contact.tmpl")

// handleContactPage serves the contact form page and processes submissions.
// GET/POST /server/contact
func (s *Server) handleContactPage(w http.ResponseWriter, r *http.Request) {
	s.handleContactFlow(w, r, false)
}

// handleContactAPI processes a contact form submission via the JSON API.
// POST /api/{api_version}/server/contact
func (s *Server) handleContactAPI(w http.ResponseWriter, r *http.Request) {
	s.handleContactFlow(w, r, true)
}

// HelpPageData holds the dynamic data for the /server/help page.
type HelpPageData struct {
	translatablePageData
	Name       string
	APIBase    string
	TorEnabled bool
	TorRunning bool
	OnionAddr  string
	I2PRunning bool
	I2PAddr    string
	CustomHTML string
	MorePages  []pageRegistryEntry
}

var helpTmpl = mustParseTemplate("help", "page/help.tmpl")

const defaultHelpContent = `# caswhois Help

caswhois looks up WHOIS and RDAP records for domains, IPv4 and IPv6 addresses, and Autonomous System Numbers. RDAP is tried first when available, with WHOIS fallback.

## Lookup

Enter a domain name, IP address, or ASN in the lookup form. The service validates the query, checks its cache and stored records, and fetches fresh data when needed.

## API and CLI

Use the REST API, GraphQL endpoint, MCP tools, or the companion caswhois-cli client. API documentation is available at /server/docs.

## Privacy and ownership

Lookups are rate limited. Resource management uses owner tokens; the service has no user accounts. See /server/privacy for data handling details.`

// handleHelpPage serves the help page.
// GET /server/help
func (s *Server) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	tor := s.buildTorInfo()
	torEnabled := tor.Enabled
	torRunning := tor.Running
	onionAddr := tor.Hostname
	data := HelpPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		APIBase:              s.config.APIBasePath(),
		TorEnabled:           torEnabled,
		TorRunning:           torRunning,
		OnionAddr:            onionAddr,
		I2PRunning:           func() bool { svc := s.currentI2P(); return svc != nil && svc.Status() == "running" }(),
		I2PAddr: func() string {
			if s.config.I2P.Expose {
				if svc := s.currentI2P(); svc != nil {
					return svc.Address()
				}
			}
			return ""
		}(),
		CustomHTML: helpPageContent(s, r),
		MorePages:  s.registeredPages("help"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(helpTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// handleHelpAPI serves the help content as JSON/plain text.
// GET /api/{api_version}/server/help
func (s *Server) handleHelpAPI(w http.ResponseWriter, r *http.Request) {
	content := helpPageContent(s, r)
	registered := s.registeredPages("help")
	pages := make([]map[string]string, 0, len(registered))
	for _, page := range registered {
		pages = append(pages, map[string]string{"path": page.Path, "title": translateKey(LangFromContext(r.Context()), page.TitleKey)})
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
		return
	}
	SendSuccess(w, map[string]any{"title": s.brandName() + " Help", "content": content, "format": "markdown", "pages": pages})
}

func helpPageContent(s *Server, r *http.Request) string {
	content, _, ok := resolvedPageContent(s.config.Pages.Help.Content, "markdown", LangFromContext(r.Context()))
	if !ok {
		content = defaultHelpContent
	}
	return substitutePageVariables(s, r, content)
}

// TermsPageData holds the dynamic data for the /server/terms page.
type TermsPageData struct {
	translatablePageData
	Name    string
	Content string
}

var termsTmpl = mustParseTemplate("terms", "page/terms.tmpl")

// defaultTermsContent is used when server.pages.terms.content is empty
// (AI.md PART 16 — /server/terms: "Default template provided, customizable via API").
const defaultTermsContent = `By using this service you agree to these terms.

## Acceptable use
Use this service only for lawful WHOIS, RDAP, IP, and ASN lookups. Do not use it to abuse, overload, or circumvent rate limits, or to violate the terms of upstream registries and registrars.

## Liability
This service is provided "as is", without warranty of any kind. We are not liable for inaccuracies in WHOIS/RDAP data returned by upstream registries, or for any damages arising from use of this service.

## Changes
These terms may be updated at any time. Continued use of the service after a change constitutes acceptance of the revised terms.

## Governing law
These terms are governed by the laws of the jurisdiction in which the service operator resides, without regard to conflict-of-law principles.`

// handleTermsPage serves the terms of service page.
// GET /server/terms
func (s *Server) handleTermsPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	content := defaultTermsContent
	data := TermsPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		Content:              content,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(termsTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

// handleTermsAPI serves the terms of service content as JSON/plain text.
// GET /api/{api_version}/server/terms
func (s *Server) handleTermsAPI(w http.ResponseWriter, r *http.Request) {
	content, format, _ := resolvedPageContent(s.config.Branding.Content.Terms.Body, s.config.Branding.Content.Terms.Format, LangFromContext(r.Context()))
	if content == "" {
		content = defaultTermsContent
	}
	content = substitutePageVariables(s, r, content)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
		return
	}
	SendSuccess(w, map[string]string{"title": "Terms of Service", "content": content, "format": format})
}

type dpoPageData struct {
	translatablePageData
	AppName string
	Name    string
	Email   string
}

var dpoTmpl = mustParseTemplate("dpo", "page/dpo.tmpl")

func (s *Server) dpoContact() (string, string) {
	name := s.config.Contact.DPO.Name
	email := s.config.Contact.DPO.Email
	if email == "" {
		email = s.config.Contact.General.Email
	}
	return name, email
}

func (s *Server) handleDPOPage(w http.ResponseWriter, r *http.Request) {
	name, email := s.dpoContact()
	data := dpoPageData{
		translatablePageData: s.newPageData(w, r),
		AppName:              s.brandName(),
		Name:                 name,
		Email:                email,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(dpoTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) handleDPOAPI(w http.ResponseWriter, r *http.Request) {
	name, email := s.dpoContact()
	SendSuccess(w, map[string]string{
		"name":        name,
		"email":       email,
		"privacy_url": s.BuildURL(r, "/server/privacy"),
	})
}

type securityPageData struct {
	translatablePageData
	AppName           string
	Email             string
	ReportURL         string
	SecurityReportURL string
	PolicyURL         string
	SecurityTxt       string
	Expires           string
	Policy            string
}

var securityTmpl = mustParseTemplate("security", "page/security.tmpl")
var securityPolicyTmpl = mustParseTemplate("security-policy", "page/security_policy.tmpl")

const disclosurePolicy = `## Reporting a vulnerability

Use this policy to report vulnerabilities in caswhois. Include the affected version, a clear description, and steps to reproduce. Please avoid accessing, changing, or deleting data that belongs to others, and stop testing if you encounter sensitive information.

We will review good-faith reports and coordinate a fix and disclosure with the reporter. Do not include secrets or personal data in a report.`

func (s *Server) securityEmail() string {
	if s.config.Contact.Security.Email != "" {
		return s.config.Contact.Security.Email
	}
	return ""
}

func (s *Server) securityExpires(now time.Time) string {
	if s.config.Web.Security.Expires != "" {
		return s.config.Web.Security.Expires
	}
	return now.AddDate(1, 0, 0).UTC().Format("2006-01-02T15:04:05Z")
}

func (s *Server) securityPolicy() string {
	if s.config.Web.Security.Policy != "" {
		return s.config.Web.Security.Policy
	}
	return disclosurePolicy
}

func (s *Server) handleSecurityPage(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	reportURL := s.config.Web.Security.ReportURL
	if reportURL == "" {
		reportURL = constants.RepoURL + "/security/advisories/new"
	}
	data := securityPageData{
		translatablePageData: s.newPageData(w, r),
		AppName:              s.brandName(),
		Email:                s.securityEmail(),
		ReportURL:            reportURL,
		SecurityReportURL:    s.securityReportURL(r.Context(), r, now),
		PolicyURL:            s.BuildURL(r, "/server/security/policy"),
		SecurityTxt:          s.BuildURL(r, "/.well-known/security.txt"),
		Expires:              s.securityExpires(now),
		Policy:               s.securityPolicy(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(securityTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) handleSecurityPolicyPage(w http.ResponseWriter, r *http.Request) {
	data := securityPageData{
		translatablePageData: s.newPageData(w, r),
		AppName:              s.brandName(),
		Email:                s.securityEmail(),
		Policy:               s.securityPolicy(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(securityPolicyTmpl, w, r, data); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func (s *Server) handleSecurityAPI(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	reportURL := s.config.Web.Security.ReportURL
	if reportURL == "" {
		reportURL = constants.RepoURL + "/security/advisories/new"
	}
	contacts := make([]map[string]string, 0, 3)
	contacts = append(contacts, map[string]string{"type": "github", "value": reportURL})
	if contactURL := s.securityReportURL(r.Context(), r, now); contactURL != "" {
		contacts = append(contacts, map[string]string{"type": "contact_form", "value": contactURL})
	}
	if email := s.securityEmail(); email != "" {
		contacts = append(contacts, map[string]string{"type": "email", "value": "mailto:" + email})
	}
	response := map[string]interface{}{
		"contacts":         contacts,
		"expires":          s.securityExpires(now),
		"policy_url":       s.BuildURL(r, "/server/security/policy"),
		"thanks_url":       s.BuildURL(r, "/server/security/thanks"),
		"security_txt_url": s.BuildURL(r, "/.well-known/security.txt"),
		"policy":           s.securityPolicy(),
	}
	fingerprint := security.PGPPublicKeyFingerprint(s.config.ConfigDir)
	pgp := map[string]any{"available": false, "url": nil, "fingerprint": nil}
	if security.PGPKeypairExists(s.config.ConfigDir) && fingerprint != "" {
		pgp = map[string]any{"available": true, "url": s.BuildURL(r, "/.well-known/pgp-key.asc"), "fingerprint": strings.ToUpper(fingerprint)}
	}
	response["pgp"] = pgp
	if s.config.Pages.Contact.Enabled {
		response["report_url"] = s.BuildURL(r, "/server/contact")
	}
	SendSuccess(w, response)
}

func (s *Server) handlePGPPublicKey(w http.ResponseWriter, r *http.Request) {
	if !security.PGPKeypairExists(s.config.ConfigDir) || security.PGPPublicKeyFingerprint(s.config.ConfigDir) == "" {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.config.ConfigDir, "security", security.PGPPublicKeyFile)
	key, err := os.ReadFile(path)
	if err != nil || security.ValidatePGPPublicKey(key) != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(key)
}

// handleAuthCheckAPI validates a bearer token without updating owner-token use
// timestamps or returning any portion of the token.
func (s *Server) handleAuthCheckAPI(w http.ResponseWriter, r *http.Request) {
	if s.authFailureBlocked(w, r) {
		return
	}
	token := extractBearerToken(r)
	if token == "" {
		if s.recordAuthFailure(w, r) {
			return
		}
		SendError(w, ErrUnauthorized, "Invalid token")
		return
	}
	incoming := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(incoming[:], s.getServerTokenHash()) == 1 {
		SendSuccess(w, map[string]string{"kind": "operator"})
		return
	}
	if strings.HasPrefix(token, "own_") && len(token) == 36 {
		var kind string
		var expires, revoked sql.NullInt64
		err := s.database.Read().QueryRowContext(r.Context(), `SELECT kind, expires_at, revoked_at FROM api_tokens WHERE token_hash = ?`, hex.EncodeToString(incoming[:])).Scan(&kind, &expires, &revoked)
		if err == nil && (kind == "primary" || kind == "linked") && !revoked.Valid && (!expires.Valid || expires.Int64 > time.Now().UTC().Unix()) {
			SendSuccess(w, map[string]string{"kind": "owner"})
			return
		}
		if err != nil && err != sql.ErrNoRows {
			SendError(w, ErrServerError, "Token validation unavailable")
			return
		}
	}
	if s.recordAuthFailure(w, r) {
		return
	}
	SendError(w, ErrUnauthorized, "Invalid token")
}

func (s *Server) handleSecurityPolicyAPI(w http.ResponseWriter, r *http.Request) {
	SendSuccess(w, map[string]string{"policy": s.securityPolicy()})
}
