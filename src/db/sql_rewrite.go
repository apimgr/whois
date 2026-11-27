package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"

	"github.com/tursodatabase/libsql-client-go/libsql"
)

const libSQLDriverName = "apimgr-libsql"

var schemaObjectNames = map[string]struct{}{
	"api_tokens": {}, "api_tokens_legacy": {}, "app_secrets": {}, "audit_log": {}, "backups": {},
	"captcha_challenges": {}, "config": {}, "config_meta": {}, "owners": {},
	"rate_limit_events": {}, "rate_limits": {}, "scheduler_history": {},
	"scheduler_tasks": {}, "security_reports": {}, "security_thanks": {},
	"whois_records":         {},
	"idx_api_tokens_active": {}, "idx_api_tokens_hash": {}, "idx_api_tokens_linked_owner_name": {}, "idx_api_tokens_resource": {},
	"idx_api_tokens_owner": {}, "idx_api_tokens_prefix": {}, "idx_api_tokens_primary": {},
	"idx_audit_log_category": {}, "idx_audit_log_timestamp": {}, "idx_backups_created": {},
	"idx_captcha_challenges_expires": {}, "idx_config_key": {},
	"idx_rate_limit_events_key_time": {}, "idx_rate_limit_events_time": {},
	"idx_rate_limits_window": {}, "idx_scheduler_history_started": {}, "idx_scheduler_history_task": {},
	"idx_security_reports_status": {}, "idx_whois_records_asn_number": {},
	"idx_whois_records_country": {}, "idx_whois_records_email": {}, "idx_whois_records_expiry": {},
	"idx_whois_records_last_seen": {}, "idx_whois_records_name": {},
	"idx_whois_records_network_range": {}, "idx_whois_records_org": {}, "idx_whois_records_query": {},
}

func init() {
	sql.Register(libSQLDriverName, prefixedLibSQLDriver{base: libsql.Driver{}})
}

// DatabaseObjectName maps a canonical schema table or index name to its
// database-specific name (AI.md PART 10). SQLite uses canonical names; remote
// libSQL/Turso objects use the srv_ prefix.
func DatabaseObjectName(driverName, name string) string {
	if NormalizeDriver(driverName) != "libsql" || strings.HasPrefix(name, "srv_") {
		return name
	}
	if _, ok := schemaObjectNames[name]; !ok {
		return name
	}
	return "srv_" + name
}

func rewriteLibSQLQuery(query string) string {
	var output strings.Builder
	output.Grow(len(query) + 32)
	for i := 0; i < len(query); {
		if query[i] == '-' && i+1 < len(query) && query[i+1] == '-' {
			end := i + 2
			for end < len(query) && query[end] != '\n' {
				end++
			}
			output.WriteString(query[i:end])
			i = end
			continue
		}
		if query[i] == '/' && i+1 < len(query) && query[i+1] == '*' {
			end := i + 2
			for end+1 < len(query) && query[end:end+2] != "*/" {
				end++
			}
			if end+1 < len(query) {
				end += 2
			} else {
				end = len(query)
			}
			output.WriteString(query[i:end])
			i = end
			continue
		}
		if query[i] == '\'' || query[i] == '"' || query[i] == '`' || query[i] == '[' {
			open := query[i]
			close := open
			if open == '[' {
				close = ']'
			}
			end := i + 1
			for end < len(query) {
				if query[end] == close {
					if close != ']' && end+1 < len(query) && query[end+1] == close {
						end += 2
						continue
					}
					break
				}
				end++
			}
			if end == len(query) {
				output.WriteString(query[i:])
				break
			}
			content := query[i+1 : end]
			if open == '\'' {
				output.WriteByte(open)
				output.WriteString(DatabaseObjectName("libsql", content))
				output.WriteByte(close)
			} else {
				output.WriteByte(open)
				output.WriteString(DatabaseObjectName("libsql", content))
				output.WriteByte(close)
			}
			i = end + 1
			continue
		}
		if isSQLIdentifierStart(query[i]) {
			end := i + 1
			for end < len(query) && isSQLIdentifierPart(query[end]) {
				end++
			}
			output.WriteString(DatabaseObjectName("libsql", query[i:end]))
			i = end
			continue
		}
		output.WriteByte(query[i])
		i++
	}
	return output.String()
}

func isSQLIdentifierStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isSQLIdentifierPart(value byte) bool {
	return isSQLIdentifierStart(value) || value >= '0' && value <= '9' || value == '$'
}

type prefixedLibSQLDriver struct {
	base driver.Driver
}

func (d prefixedLibSQLDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.base.Open(name)
	if err != nil {
		return nil, err
	}
	return prefixedLibSQLConn{Conn: conn}, nil
}

type prefixedLibSQLConn struct {
	driver.Conn
}

func (c prefixedLibSQLConn) Prepare(query string) (driver.Stmt, error) {
	return c.Conn.Prepare(rewriteLibSQLQuery(query))
}

func (c prefixedLibSQLConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	query = rewriteLibSQLQuery(query)
	if conn, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return conn.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func (c prefixedLibSQLConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if conn, ok := c.Conn.(driver.ConnBeginTx); ok {
		return conn.BeginTx(ctx, options)
	}
	if options.Isolation != driver.IsolationLevel(sql.LevelDefault) || options.ReadOnly {
		return nil, driver.ErrSkip
	}
	//lint:ignore SA1019 Legacy drivers may implement Conn.Begin without ConnBeginTx.
	return nil, driver.ErrSkip
}

func (c prefixedLibSQLConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	conn, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return conn.ExecContext(ctx, rewriteLibSQLQuery(query), args)
}

func (c prefixedLibSQLConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	conn, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return conn.QueryContext(ctx, rewriteLibSQLQuery(query), args)
}

func (c prefixedLibSQLConn) CheckNamedValue(value *driver.NamedValue) error {
	if checker, ok := c.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

func (c prefixedLibSQLConn) Ping(ctx context.Context) error {
	if pinger, ok := c.Conn.(driver.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (c prefixedLibSQLConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c prefixedLibSQLConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}
