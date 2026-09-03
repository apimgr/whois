package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/apimgr/whois/src/common/constants"
	"github.com/apimgr/whois/src/email"
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
	Content               string
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

var privacyTmpl = mustParseTemplate("privacy", "privacy.html")

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
	dataCollection := p.Content.DataCollection
	if dataCollection == "" {
		dataCollection = "We collect only the data necessary to operate the service, such as request logs and, where enabled, anonymized analytics."
	}
	dataSecurity := p.Content.DataSecurity
	if dataSecurity == "" {
		dataSecurity = "We use industry-standard security practices, including encryption in transit, to protect your data."
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
		DataCollection:        dataCollection,
		DataUsage:             dataUsage,
		DataSecurity:          dataSecurity,
		RetentionPeriod:       p.Retention.Period,
		ExportAvailable:       p.Retention.ExportAvailable,
		DeletionAvailable:     p.Retention.DeletionAvailable,
		ThirdPartyServices:    services,
		CCPAApplicable:        p.IsCCPAApplicable(),
		CCPAOptedOut:          ccpaOptedOut(r),
		Content:               s.config.Pages.Privacy.Content,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(privacyTmpl, w, r, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
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
		// Override holds the full Markdown page override from
		// server.pages.privacy.content; empty when the default template is used.
		Override string `json:"override,omitempty"`
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
	resp.Content.Override = s.config.Pages.Privacy.Content

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data_sold: " + boolStr(resp.Summary.DataSold) + "\n"))
		w.Write([]byte("data_stored_on_server: " + boolStr(resp.Summary.DataStoredOnServer) + "\n"))
		w.Write([]byte("ccpa_applicable: " + boolStr(resp.CCPA.Applicable) + "\n"))
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
	Name           string
	Enabled        bool
	Captcha        string
	SuccessMessage string
	Submitted      bool
	AbuseEmail     string
}

var contactTmpl = mustParseTemplate("contact", "contact.html")

// handleContactPage serves the contact form page and processes submissions.
// GET/POST /server/contact
func (s *Server) handleContactPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	submitted := false
	if r.Method == http.MethodPost {
		s.processContactSubmission(r)
		submitted = true
	}
	abuseEmail := s.config.Contact.Abuse.Email
	if abuseEmail == "" {
		abuseEmail = s.config.Contact.General.Email
	}
	successMsg := s.config.Pages.Contact.SuccessMessage
	if successMsg == "" {
		successMsg = "Thank you for your message. We'll respond soon."
	}
	captcha := s.config.Pages.Contact.Captcha
	if captcha == "" {
		captcha = "simple"
	}
	data := ContactPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		Enabled:              s.config.Pages.Contact.Enabled,
		Captcha:              captcha,
		SuccessMessage:       successMsg,
		Submitted:            submitted,
		AbuseEmail:           abuseEmail,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(contactTmpl, w, r, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// processContactSubmission validates and routes a contact form submission to
// server.contact.general.email, falling back to server.contact.admin.email
// when general is unset (AI.md PART 16 — /server/contact, Configuration).
func (s *Server) processContactSubmission(r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	senderEmail := strings.TrimSpace(r.FormValue("email"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	if name == "" || senderEmail == "" || subject == "" || message == "" {
		return
	}
	recipient := s.config.Contact.General.Email
	if recipient == "" {
		recipient = s.config.Contact.Admin.Email
	}
	if recipient == "" || s.email == nil {
		return
	}
	appName := s.config.Branding.Title
	if appName == "" {
		appName = constants.InternalName
	}
	_ = s.email.SendEmail(recipient, "contact", email.EmailData{
		"subject":      subject,
		"app_name":     appName,
		"fqdn":         s.config.FQDN,
		"app_url":      s.config.FQDN,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"sender_name":  name,
		"sender_email": senderEmail,
		"message":      message,
	})
}

// handleContactAPI processes a contact form submission via the JSON API.
// POST /api/{api_version}/server/contact
func (s *Server) handleContactAPI(w http.ResponseWriter, r *http.Request) {
	if !s.config.Pages.Contact.Enabled {
		SendError(w, ErrForbidden, "contact form is disabled")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(r.FormValue("email"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	if name == "" || email == "" || subject == "" || message == "" {
		SendError(w, ErrValidationFailed, "name, email, subject, and message are required")
		return
	}
	s.processContactSubmission(r)
	successMsg := s.config.Pages.Contact.SuccessMessage
	if successMsg == "" {
		successMsg = "Thank you for your message. We'll respond soon."
	}
	SendSuccess(w, map[string]string{"message": successMsg})
}

// HelpPageData holds the dynamic data for the /server/help page.
type HelpPageData struct {
	translatablePageData
	Name       string
	APIBase    string
	TorEnabled bool
	TorRunning bool
	OnionAddr  string
	CustomHTML string
}

var helpTmpl = mustParseTemplate("help", "help.html")

// handleHelpPage serves the help page.
// GET /server/help
func (s *Server) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	name := s.config.Branding.Title
	if name == "" {
		name = constants.InternalName
	}
	torEnabled := s.torService != nil
	torRunning := false
	onionAddr := ""
	if s.torService != nil {
		onionAddr = s.torService.OnionAddress()
		torRunning = onionAddr != "" && onionAddr != ".onion"
	}
	data := HelpPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		APIBase:              s.config.APIBasePath(),
		TorEnabled:           torEnabled,
		TorRunning:           torRunning,
		OnionAddr:            onionAddr,
		CustomHTML:           s.config.Pages.Help.Content,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(helpTmpl, w, r, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleHelpAPI serves the help content as JSON/plain text.
// GET /api/{api_version}/server/help
func (s *Server) handleHelpAPI(w http.ResponseWriter, r *http.Request) {
	content := s.config.Pages.Help.Content
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
		return
	}
	SendSuccess(w, map[string]string{"content": content})
}

// TermsPageData holds the dynamic data for the /server/terms page.
type TermsPageData struct {
	translatablePageData
	Name    string
	Content string
}

var termsTmpl = mustParseTemplate("terms", "terms.html")

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
	content := s.config.Pages.Terms.Content
	if content == "" {
		content = defaultTermsContent
	}
	data := TermsPageData{
		translatablePageData: s.newPageData(w, r),
		Name:                 name,
		Content:              content,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(termsTmpl, w, r, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// handleTermsAPI serves the terms of service content as JSON/plain text.
// GET /api/{api_version}/server/terms
func (s *Server) handleTermsAPI(w http.ResponseWriter, r *http.Request) {
	content := s.config.Pages.Terms.Content
	if content == "" {
		content = defaultTermsContent
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
		return
	}
	SendSuccess(w, map[string]string{"content": content})
}
