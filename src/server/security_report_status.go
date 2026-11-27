package server

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/apimgr/whois/src/security"
	"github.com/go-chi/chi/v5"
)

type securityReportStatusView struct {
	translatablePageData
	TrackingID     string
	Status         string
	Comment        string
	DisclosureDate string
}

var securityReportStatusTmpl = mustParseTemplate("security-report-status", "page/security_report_status.tmpl")

// handleSecurityReportStatus exposes only the public triage fields. The URL token
// is stored as a one-way hash and may be consumed once per UTC day.
func (s *Server) handleSecurityReportStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "tracking_id"))
	token := r.URL.Query().Get("token")
	if r.Method != http.MethodGet || !strings.HasPrefix(id, "sec_") || len(id) != 20 || token == "" || s.database == nil {
		http.NotFound(w, r)
		return
	}
	day := time.Now().UTC().Format("2006-01-02")
	var view securityReportStatusView
	err := s.database.Write(r.Context(), func(tx *sql.Tx) error {
		var hash, last, status, comment, disclosure, closed sql.NullString
		if err := tx.QueryRowContext(r.Context(), `SELECT token_hash, token_last_used, status, researcher_comment, disclosure_date, closed_at FROM security_reports WHERE tracking_id=?`, id).Scan(&hash, &last, &status, &comment, &disclosure, &closed); err != nil {
			return err
		}
		if !hash.Valid || !security.VerifyToken(token, hash.String) || (last.Valid && last.String == day) {
			return sql.ErrNoRows
		}
		if closed.Valid {
			closedAt, err := time.Parse("2006-01-02 15:04:05", closed.String)
			if err != nil {
				closedAt, err = time.Parse(time.RFC3339, closed.String)
			}
			if err == nil && time.Since(closedAt) > 30*24*time.Hour {
				return sql.ErrNoRows
			}
		}
		if _, err := tx.ExecContext(r.Context(), `UPDATE security_reports SET token_last_used=?, updated_at=updated_at WHERE tracking_id=?`, day, id); err != nil {
			return err
		}
		view = securityReportStatusView{TrackingID: id, Status: status.String, Comment: comment.String}
		if disclosure.Valid {
			view.DisclosureDate = disclosure.String
		}
		return nil
	})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view.translatablePageData = s.newPageData(w, r)
	if err := s.renderTemplate(securityReportStatusTmpl, w, r, view); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}
