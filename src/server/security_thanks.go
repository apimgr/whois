package server

import (
	"net/http"
	"time"
)

type securityThanksEntry struct {
	Credit   string `json:"credit"`
	Date     string `json:"date"`
	Severity string `json:"severity"`
	Year     string `json:"-"`
}

type securityThanksPageData struct {
	translatablePageData
	Entries []securityThanksEntry
}

var securityThanksTemplate = mustParseTemplate("security-thanks", "page/security_thanks.tmpl")

func (s *Server) securityThanksEntries() ([]securityThanksEntry, error) {
	rows, err := s.database.Read().Query(`SELECT credit, severity, disclosed_on FROM security_thanks ORDER BY disclosed_on DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]securityThanksEntry, 0)
	for rows.Next() {
		var entry securityThanksEntry
		var date string
		if err := rows.Scan(&entry.Credit, &entry.Severity, &date); err != nil {
			return nil, err
		}
		entry.Date = date
		entry.Year = securityThanksYear(date)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Server) handleSecurityThanksPage(w http.ResponseWriter, r *http.Request) {
	entries, err := s.securityThanksEntries()
	if err != nil {
		RespondError(w, r, http.StatusInternalServerError, "Unable to load security acknowledgments")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(securityThanksTemplate, w, r, securityThanksPageData{
		translatablePageData: s.newPageData(w, r),
		Entries:              entries,
	}); err != nil {
		RespondError(w, r, http.StatusInternalServerError, "Unable to render security acknowledgments")
	}
}

func (s *Server) handleSecurityThanksAPI(w http.ResponseWriter, r *http.Request) {
	entries, err := s.securityThanksEntries()
	if err != nil {
		SendError(w, ErrServerError, "Unable to load security acknowledgments")
		return
	}
	SendSuccess(w, map[string][]securityThanksEntry{"entries": entries})
}

func securityThanksYear(date string) string {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return ""
	}
	return parsed.Format("2006")
}
