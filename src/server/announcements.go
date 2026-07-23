package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dismissedAnnouncementsCookieName is the cookie tracking which announcement
// ids the visitor has already dismissed (AI.md PART 16 — Site Banner,
// Dismissal: "dismissed_announcements cookie (comma-separated ids)").
const dismissedAnnouncementsCookieName = "dismissed_announcements"

// announcementIcons maps each announcement type to its aria-hidden glyph
// (AI.md PART 16 — Site Banner, HTML Structure shows "⚠" for warning; the
// other three types follow the same convention).
var announcementIcons = map[string]string{
	"info":    "ℹ",
	"warning": "⚠",
	"error":   "⛔",
	"success": "✓",
}

// announcementRoles maps each announcement type to its ARIA role
// (AI.md PART 16 — Site Banner, Banner Behavior: "role=\"status\" for info
// and success; role=\"alert\" for warning and error").
var announcementRoles = map[string]string{
	"info":    "status",
	"warning": "alert",
	"error":   "alert",
	"success": "status",
}

// announcementView holds the values needed to render one site-banner entry
// (AI.md PART 16 — Site Banner, HTML Structure).
type announcementView struct {
	ID          string
	Type        string
	Icon        string
	Role        string
	Message     string
	Dismissible bool
	CSRFToken   string
	DismissAria string
}

// siteBannerTmpl is the embedded site-banner partial (AI.md PART 16 —
// Site Banner, HTML Structure + CSS).
var siteBannerTmpl = mustParseTemplate("site_banner", "site_banner.html")

// dismissedAnnouncementIDs reads the dismissed_announcements cookie and
// returns the set of ids already dismissed by this visitor.
func dismissedAnnouncementIDs(r *http.Request) map[string]bool {
	ids := map[string]bool{}
	c, err := r.Cookie(dismissedAnnouncementsCookieName)
	if err != nil || c.Value == "" {
		return ids
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		raw = c.Value
	}
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		if id != "" {
			ids[id] = true
		}
	}
	return ids
}

// activeAnnouncements filters web.announcements.messages down to the ones
// currently in their start-end window and not yet dismissed by this visitor
// (AI.md PART 16 — Site Banner, Banner Behavior: "Source" / "Expiry" /
// "Dismissal").
func (s *Server) activeAnnouncements(w http.ResponseWriter, r *http.Request) []announcementView {
	cfg := s.config.Web.Announcements
	if !cfg.Enabled || len(cfg.Messages) == 0 {
		return nil
	}
	dismissed := dismissedAnnouncementIDs(r)
	now := time.Now().UTC()
	csrfToken := s.csrfToken(w, r)
	lang := LangFromContext(r.Context())
	var out []announcementView
	for _, m := range cfg.Messages {
		if m.ID == "" || dismissed[m.ID] {
			continue
		}
		if m.Start != "" {
			if start, err := time.Parse(time.RFC3339, m.Start); err == nil && now.Before(start) {
				continue
			}
		}
		if m.End != "" {
			if end, err := time.Parse(time.RFC3339, m.End); err == nil && now.After(end) {
				continue
			}
		}
		mtype := m.Type
		if _, ok := announcementIcons[mtype]; !ok {
			mtype = "info"
		}
		out = append(out, announcementView{
			ID:          m.ID,
			Type:        mtype,
			Icon:        announcementIcons[mtype],
			Role:        announcementRoles[mtype],
			Message:     m.Message,
			Dismissible: m.Dismissible,
			CSRFToken:   csrfToken,
			DismissAria: translateKey(lang, "site_banner.dismiss_aria"),
		})
	}
	return out
}

// announcementsHTML renders the stacked site-banner markup for all currently
// active, non-dismissed announcements, or an empty string when there are
// none (AI.md PART 16 — Site Banner, Stacking: "Multiple active
// announcements stack in config order").
func (s *Server) announcementsHTML(w http.ResponseWriter, r *http.Request) template.HTML {
	views := s.activeAnnouncements(w, r)
	if len(views) == 0 {
		return ""
	}
	var sb strings.Builder
	if err := siteBannerTmpl.Execute(&sb, views); err != nil {
		return ""
	}
	return template.HTML(sb.String())
}

// handleAnnouncementDismiss processes the site-banner dismiss form
// (AI.md PART 16 — Site Banner, Dismissal: POST /announcements/dismiss).
// It appends the announcement id to the dismissed_announcements cookie and
// redirects back to the originating page.
func (s *Server) handleAnnouncementDismiss(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		SendError(w, ErrBadRequest, "id is required")
		return
	}
	ids := dismissedAnnouncementIDs(r)
	ids[id] = true
	list := make([]string, 0, len(ids))
	for existing := range ids {
		list = append(list, existing)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     dismissedAnnouncementsCookieName,
		Value:    url.QueryEscape(strings.Join(list, ",")),
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: false,
		Secure:   csrfCookieSecure(s.config.CSRF.Secure, r),
		SameSite: http.SameSiteLaxMode,
	})
	redirectBack(w, r, "/")
}
