package app

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/email"
	caslogger "github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/security"
	"golang.org/x/term"
)

var securityStatusOrder = map[string]int{"received": 0, "triaged": 1, "confirmed": 2, "patching": 3, "disclosed": 4, "wont_fix": 5}

func runSecurityMaintenance(args []string, configDir string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		printSecurityMaintenanceHelp()
		return 0
	}
	cfg, err := config.LoadServerConfig(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load config: %v\n", err)
		return 1
	}
	if !authorizeSecurityMaintenance(cfg) {
		return 1
	}
	_, database, err := openMaintenanceDB(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Open database: %v\n", err)
		return 1
	}
	defer func() { _ = database.Close() }()
	switch args[0] {
	case "list":
		return securityReportList(database, args[1:])
	case "show":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: --maintenance 'security show TRACKING_ID'")
			return 1
		}
		return securityReportShow(database, args[1])
	case "export":
		return securityReportExport(cfg, database, args[1:])
	case "update":
		return securityReportUpdate(cfg, database, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown security action %q\n", args[0])
		printSecurityMaintenanceHelp()
		return 1
	}
}

func printSecurityMaintenanceHelp() {
	fmt.Println("Security report maintenance:")
	fmt.Println("  security list [--status STATUS]")
	fmt.Println("  security show TRACKING_ID")
	fmt.Println("  security export TRACKING_ID [--output FILE|-]")
	fmt.Println("  security update TRACKING_ID [--status STATUS] [--comment TEXT] [--disclosure-date YYYY-MM-DD] [--severity LEVEL]")
}

func authorizeSecurityMaintenance(cfg *config.ServerConfig) bool {
	return authorizeOperatorMaintenance(cfg, "Security maintenance")
}

func authorizeOperatorMaintenance(cfg *config.ServerConfig, action string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	if cfg.ServerToken == "" {
		fmt.Fprintf(os.Stderr, "%s requires root or the operator token.\n", action)
		return false
	}
	fmt.Fprint(os.Stderr, "Operator token: ")
	var supplied []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return false
		}
		supplied = value
	} else {
		var value string
		if _, err := fmt.Fscan(os.Stdin, &value); err != nil {
			return false
		}
		supplied = []byte(value)
	}
	return subtle.ConstantTimeCompare(supplied, []byte(cfg.ServerToken)) == 1
}

func logSecurityMaintenance(cfg *config.ServerConfig, event, details string) {
	logger, err := caslogger.Open(cfg.GetLogDir())
	if err != nil {
		return
	}
	defer logger.Close()
	logger.WriteSecurity(event + " " + details)
}

func securityReportList(database *db.DB, args []string) int {
	status := ""
	if len(args) > 0 {
		if len(args) != 2 || args[0] != "--status" || !validSecurityStatus(args[1]) {
			fmt.Fprintln(os.Stderr, "Usage: --maintenance 'security list [--status STATUS]'")
			return 1
		}
		status = args[1]
	}
	query := "SELECT tracking_id,status,severity,component,created_at,updated_at FROM security_reports"
	var rows *sql.Rows
	var err error
	if status != "" {
		rows, err = database.Read().Query(query+" WHERE status=? ORDER BY created_at", status)
	} else {
		rows, err = database.Read().Query(query + " ORDER BY created_at")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "List reports: %v\n", err)
		return 1
	}
	defer func() { _ = rows.Close() }()
	fmt.Println("TRACKING_ID\tSTATUS\tSEVERITY\tCOMPONENT\tCREATED\tUPDATED")
	for rows.Next() {
		var id, st, severity, component, created, updated string
		if err := rows.Scan(&id, &st, &severity, &component, &created, &updated); err != nil {
			fmt.Fprintf(os.Stderr, "Read report: %v\n", err)
			return 1
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", id, st, severity, component, created, updated)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Read reports: %v\n", err)
		return 1
	}
	return 0
}

func securityReportShow(database *db.DB, id string) int {
	var status, severity, component, comment, created, updated string
	var disclosure sql.NullString
	err := database.Read().QueryRow("SELECT status,severity,component,researcher_comment,disclosure_date,created_at,updated_at FROM security_reports WHERE tracking_id=?", id).Scan(&status, &severity, &component, &comment, &disclosure, &created, &updated)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report not found or unreadable: %v\n", err)
		return 1
	}
	fmt.Printf("Tracking ID: %s\nStatus: %s\nSeverity: %s\nComponent: %s\nCreated: %s\nUpdated: %s\n", id, status, severity, component, created, updated)
	if disclosure.Valid {
		fmt.Printf("Disclosure date: %s\n", disclosure.String)
	}
	fmt.Printf("Researcher comment:\n%s\n", comment)
	return 0
}

func securityReportExport(cfg *config.ServerConfig, database *db.DB, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: --maintenance 'security export TRACKING_ID [--output FILE|-]'")
		return 1
	}
	id := args[0]
	output := ""
	if len(args) > 1 {
		if len(args) != 3 || args[1] != "--output" {
			fmt.Fprintln(os.Stderr, "Invalid export options")
			return 1
		}
		output = args[2]
	}
	var encrypted []byte
	if err := database.Read().QueryRow("SELECT body_enc FROM security_reports WHERE tracking_id=?", id).Scan(&encrypted); err != nil {
		fmt.Fprintf(os.Stderr, "Report not found: %v\n", err)
		return 1
	}
	if output == "-" {
		if _, err := os.Stdout.Write(encrypted); err != nil {
			fmt.Fprintf(os.Stderr, "Write encrypted report: %v\n", err)
			return 1
		}
	} else {
		if output == "" {
			output = id + ".asc"
		}
		file, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create export: %v\n", err)
			return 1
		}
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(encrypted)
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Write encrypted report: %v\n", err)
			return 1
		}
	}
	logSecurityMaintenance(cfg, "security.report_exported", fmt.Sprintf("tracking_id=%q", id))
	return 0
}

type securityUpdateOptions struct {
	status, comment, disclosureDate, severity   string
	statusSet, commentSet, dateSet, severitySet bool
}

func parseSecurityUpdate(args []string) (string, securityUpdateOptions, error) {
	if len(args) < 1 {
		return "", securityUpdateOptions{}, errors.New("tracking ID is required")
	}
	id := args[0]
	var result securityUpdateOptions
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--status":
			if i+1 >= len(args) {
				return "", result, errors.New("--status needs a value")
			}
			i++
			result.status = args[i]
			result.statusSet = true
		case "--severity":
			if i+1 >= len(args) {
				return "", result, errors.New("--severity needs a value")
			}
			i++
			result.severity = args[i]
			result.severitySet = true
		case "--disclosure-date":
			if i+1 >= len(args) {
				return "", result, errors.New("--disclosure-date needs a value")
			}
			i++
			result.disclosureDate = args[i]
			result.dateSet = true
		case "--comment":
			if i+1 >= len(args) {
				return "", result, errors.New("--comment needs a value")
			}
			i++
			result.comment = strings.Trim(strings.Join(args[i:], " "), "'\"")
			result.commentSet = true
			i = len(args)
		default:
			return "", result, fmt.Errorf("unknown update option %q", args[i])
		}
	}
	return id, result, nil
}

func validSecurityStatus(status string) bool { _, ok := securityStatusOrder[status]; return ok }
func validSecuritySeverity(level string) bool {
	switch level {
	case "critical", "high", "medium", "low", "informational":
		return true
	}
	return false
}
func validSecurityTransition(oldStatus, newStatus string) bool {
	if !validSecurityStatus(oldStatus) || !validSecurityStatus(newStatus) {
		return false
	}
	if oldStatus == "disclosed" || oldStatus == "wont_fix" {
		return oldStatus == newStatus
	}
	if newStatus == "wont_fix" {
		return true
	}
	return securityStatusOrder[newStatus] >= securityStatusOrder[oldStatus]
}

func securityReportUpdate(cfg *config.ServerConfig, database *db.DB, args []string) int {
	id, change, err := parseSecurityUpdate(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if change.commentSet && len([]rune(change.comment)) > 2000 {
		fmt.Fprintln(os.Stderr, "Comment exceeds 2000 characters")
		return 1
	}
	if change.statusSet && !validSecurityStatus(change.status) {
		fmt.Fprintln(os.Stderr, "Invalid status")
		return 1
	}
	if change.severitySet && !validSecuritySeverity(change.severity) {
		fmt.Fprintln(os.Stderr, "Invalid severity")
		return 1
	}
	if change.dateSet {
		if _, err := time.Parse("2006-01-02", change.disclosureDate); err != nil {
			fmt.Fprintln(os.Stderr, "Disclosure date must be YYYY-MM-DD")
			return 1
		}
	}
	ctx := context.Background()
	var oldStatus, oldSeverity, creditPref string
	var creditName, oldDisclosure, contactEnc sql.NullString
	err = database.Write(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT status,severity,disclosure_date,credit_pref,credit_name,contact_enc FROM security_reports WHERE tracking_id=?", id).Scan(&oldStatus, &oldSeverity, &oldDisclosure, &creditPref, &creditName, &contactEnc); err != nil {
			return err
		}
		newStatus := oldStatus
		if change.statusSet {
			newStatus = change.status
		}
		if !validSecurityTransition(oldStatus, newStatus) {
			return fmt.Errorf("status cannot move backward from %s to %s", oldStatus, newStatus)
		}
		severity := oldSeverity
		if change.severitySet {
			severity = change.severity
		}
		var comment string
		if err := tx.QueryRowContext(ctx, "SELECT researcher_comment FROM security_reports WHERE tracking_id=?", id).Scan(&comment); err != nil {
			return err
		}
		if change.commentSet {
			comment = change.comment
		}
		var disclosure any
		if oldDisclosure.Valid {
			disclosure = oldDisclosure.String
		}
		if change.dateSet {
			disclosure = change.disclosureDate
		}
		closed := newStatus == "disclosed" || newStatus == "wont_fix"
		if _, err := tx.ExecContext(ctx, "UPDATE security_reports SET status=?,severity=?,researcher_comment=?,disclosure_date=?,updated_at=CURRENT_TIMESTAMP,closed_at=CASE WHEN ? THEN COALESCE(closed_at,CURRENT_TIMESTAMP) ELSE closed_at END WHERE tracking_id=?", newStatus, severity, comment, disclosure, closed, id); err != nil {
			return err
		}
		if newStatus == "disclosed" && oldStatus != "disclosed" && creditPref != "no" {
			credit := ""
			if creditPref == "anon" {
				var count int
				if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_thanks WHERE credit LIKE 'Anonymous Researcher #%';").Scan(&count); err != nil {
					return err
				}
				credit = fmt.Sprintf("Anonymous Researcher #%d", count+1)
			} else if creditName.Valid {
				credit = creditName.String
			}
			if credit != "" {
				if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO security_thanks(tracking_id,credit,severity,disclosed_on) VALUES(?,?,?,?)", id, credit, severity, time.Now().UTC().Format("2006-01-02")); err != nil {
					return err
				}
			}
		}
		oldSeverity = severity
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update report: %v\n", err)
		return 1
	}
	var newStatus string
	if err := database.Read().QueryRowContext(ctx, "SELECT status FROM security_reports WHERE tracking_id=?", id).Scan(&newStatus); err != nil {
		fmt.Fprintf(os.Stderr, "Read updated report: %v\n", err)
		return 1
	}
	logSecurityMaintenance(cfg, "security.report_updated", fmt.Sprintf("tracking_id=%q old_status=%q new_status=%q", id, oldStatus, newStatus))
	if newStatus != oldStatus && contactEnc.Valid {
		securityReportStatusNotice(cfg, contactEnc.String, id, newStatus)
	}
	fmt.Printf("%s Updated security report %s\n", okMark(), id)
	return 0
}

func securityReportStatusNotice(cfg *config.ServerConfig, contactEnc, id, status string) {
	if contactEnc == "" {
		return
	}
	key, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil {
		return
	}
	plaintext, err := security.DecryptAESGCM(key, contactEnc)
	if err != nil {
		return
	}
	var contact struct{ Email string }
	if json.Unmarshal([]byte(plaintext), &contact) != nil || contact.Email == "" {
		return
	}
	em := email.NewEmailManager(cfg.ConfigDir)
	smtp := cfg.Notifications.Email.SMTP
	from := cfg.Notifications.Email.From
	if smtp.Host != "" {
		em.Configure(smtp.Host, smtp.Port, smtp.Username, smtp.Password, smtp.TLS, from.Name, from.Email)
		if em.TestConnection() != nil {
			return
		}
		em.Enable()
	} else if !em.AutoDetectSMTP(cfg.FQDN, "") {
		return
	} else {
		em.Enable()
	}
	_ = em.SendEmail(contact.Email, "security_alert", email.EmailData{"app_name": cfg.Branding.Title, "fqdn": cfg.FQDN, "timestamp": time.Now().UTC().Format(time.RFC3339), "event": "Security report status updated", "ip": "redacted", "details": "Tracking ID: " + id + "\nStatus: " + status})
}
