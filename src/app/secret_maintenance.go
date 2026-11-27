package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/apimgr/whois/src/config"
	"github.com/apimgr/whois/src/db"
	"github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/security"
)

func handleSecretMaintenance(args []string, configDir string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Println("Secret maintenance:")
		fmt.Println("  secret rotate installation_secret")
		fmt.Println("  secret rotate encryption_key")
		return 0
	}
	if len(args) != 2 || args[0] != "rotate" {
		fmt.Fprintln(os.Stderr, "Usage: --maintenance 'secret rotate <installation_secret|encryption_key>'")
		return 1
	}
	if args[1] != "installation_secret" && args[1] != "encryption_key" {
		fmt.Fprintf(os.Stderr, "Unsupported manually-rotated secret %q\n", args[1])
		return 1
	}
	cfg, err := config.LoadServerConfig(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return 1
	}
	if configuredServerIsListening(cfg) {
		fmt.Fprintln(os.Stderr, "Stop the server before rotating secrets so it cannot continue writing with stale in-memory keys.")
		return 1
	}
	if !authorizeSecurityMaintenance(cfg) {
		return 1
	}
	reason, operatorIP, confirmed := confirmSecretRotation(args[1])
	if !confirmed {
		fmt.Fprintln(os.Stderr, "Secret rotation cancelled.")
		return 1
	}
	database, err := initDatabase(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		return 1
	}
	defer func() { _ = database.Close() }()
	ctx := context.Background()
	var event string
	switch args[1] {
	case "installation_secret":
		event = "security.installation_secret_rotated"
		err = rotateInstallationSecret(ctx, database, cfg.ConfigDir)
	case "encryption_key":
		event = "security.encryption_key_rotated"
		err = rotateEncryptionKey(ctx, database, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported manually-rotated secret %q\n", args[1])
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Secret rotation failed: %v\n", err)
		return 1
	}
	if err := writeSecretRotationAudit(ctx, database, cfg, event, operatorIP, reason); err != nil {
		fmt.Fprintf(os.Stderr, "Secret rotated but audit logging failed: %v\n", err)
		return 1
	}
	fmt.Printf("%s %s rotated successfully\n", okMark(), args[1])
	return 0
}

func configuredServerIsListening(cfg *config.ServerConfig) bool {
	ports := []int{cfg.HTTPPort, cfg.HTTPSPort}
	if cfg.Port > 0 {
		ports = append(ports, cfg.Port)
	}
	host := strings.Trim(strings.TrimSpace(cfg.Address), "[]")
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		host = "127.0.0.1"
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	local := map[string]bool{"127.0.0.1": true, "::1": true}
	if addresses, addrErr := net.InterfaceAddrs(); addrErr == nil {
		for _, address := range addresses {
			ip, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil && ip != nil {
				local[ip.String()] = true
			}
		}
	}
	for _, ip := range ips {
		if !local[ip.String()] {
			continue
		}
		for _, port := range ports {
			if port <= 0 {
				continue
			}
			connection, dialErr := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), fmt.Sprint(port)), 150*time.Millisecond)
			if dialErr == nil {
				_ = connection.Close()
				return true
			}
		}
	}
	return false
}

func confirmSecretRotation(name string) (string, string, bool) {
	scanner := bufio.NewScanner(os.Stdin)
	readLine := func(prompt string) string {
		fmt.Fprint(os.Stderr, prompt)
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			if value != "" {
				return value
			}
		}
		return ""
	}
	reason := readLine("Reason for rotation: ")
	if reason == "" {
		return "", "", false
	}
	confirmation := readLine("Type ROTATE " + name + " to confirm: ")
	if confirmation != "ROTATE "+name {
		return "", "", false
	}
	return sanitizeRotationReason(reason), localOperatorIP(), true
}

func sanitizeRotationReason(reason string) string {
	var result strings.Builder
	for _, r := range reason {
		if result.Len() >= 200 {
			break
		}
		if r >= 0x20 && r != 0x7f {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

func localOperatorIP() string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip != nil && !ip.IsLoopback() && ip.IsGlobalUnicast() {
			return ip.String()
		}
	}
	return "unknown"
}

func rotateInstallationSecret(ctx context.Context, database *db.DB, configDir string) error {
	oldSecret, err := database.AppSecret(ctx, "installation_secret")
	if err != nil {
		return err
	}
	if err := refuseActivePreviousSecret(ctx, database, "installation_secret"); err != nil {
		return err
	}
	newSecret := make([]byte, 32)
	if _, err := rand.Read(newSecret); err != nil {
		return fmt.Errorf("generate installation secret: %w", err)
	}
	if err := saveRotatedAppSecret(ctx, database, "installation_secret", oldSecret, newSecret, 7*24*time.Hour, false); err != nil {
		return err
	}
	return resumeInstallationSecretRotation(ctx, database, configDir)
}

func rotateEncryptionKey(ctx context.Context, database *db.DB, cfg *config.ServerConfig) error {
	oldKey, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil || len(oldKey) != 32 {
		return errors.New("current server.security.encryption_key is invalid")
	}
	if err := refuseActivePreviousSecret(ctx, database, "encryption_key"); err != nil {
		return err
	}
	encodedNewKey, err := config.GenerateEncryptionKey()
	if err != nil {
		return err
	}
	newKey, err := base64.StdEncoding.DecodeString(encodedNewKey)
	if err != nil {
		return err
	}
	if err := saveRotatedAppSecret(ctx, database, "encryption_key", oldKey, newKey, 30*24*time.Hour, true); err != nil {
		return err
	}
	oldValue := cfg.Security.EncryptionKey
	cfg.Security.EncryptionKey = encodedNewKey
	cfg.Security.EncryptionKeyVersion++
	if cfg.Security.EncryptionKeyVersion < 2 {
		cfg.Security.EncryptionKeyVersion = 2
	}
	if err := cfg.SaveSecrets(cfg.ConfigDir); err != nil {
		cfg.Security.EncryptionKey = oldValue
		_ = deletePreviousSecret(ctx, database, "encryption_key")
		return fmt.Errorf("save new encryption key: %w", err)
	}
	return reencryptSensitiveRows(ctx, database, oldKey, newKey)
}

func saveRotatedAppSecret(ctx context.Context, database *db.DB, name string, previous, current []byte, grace time.Duration, wrapPrevious bool) error {
	previousValue := base64.StdEncoding.EncodeToString(previous)
	if wrapPrevious {
		wrapped, err := security.EncryptAESGCM(current, previousValue)
		if err != nil {
			return err
		}
		previousValue = wrapped
	}
	until := time.Now().UTC().Add(grace).Format(time.RFC3339)
	return database.Write(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC().Format(time.RFC3339)
		values := map[string]string{name + "_previous": previousValue, name + "_previous_until": until, name: base64.StdEncoding.EncodeToString(current)}
		for key, value := range values {
			if _, err := tx.ExecContext(ctx, `INSERT INTO app_secrets(name,value,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, now); err != nil {
				return fmt.Errorf("store rotated %s state: %w", name, err)
			}
		}
		return nil
	})
}

func refuseActivePreviousSecret(ctx context.Context, database *db.DB, name string) error {
	var until string
	err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name+"_previous_until").Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return fmt.Errorf("previous %s grace deadline is invalid", name)
	}
	if time.Now().UTC().Before(deadline) {
		return fmt.Errorf("previous %s is still within its grace period until %s", name, deadline.Format(time.RFC3339))
	}
	return deletePreviousSecret(ctx, database, name)
}

func deletePreviousSecret(ctx context.Context, database *db.DB, name string) error {
	return database.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM app_secrets WHERE name IN (?,?)`, name+"_previous", name+"_previous_until")
		return err
	})
}

func loadPreviousSecret(ctx context.Context, database *db.DB, name string, current []byte, wrapped bool) ([]byte, error) {
	var value, until string
	err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name+"_previous").Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := database.Read().QueryRowContext(ctx, `SELECT value FROM app_secrets WHERE name=?`, name+"_previous_until").Scan(&until); err != nil {
		return nil, err
	}
	if _, err := time.Parse(time.RFC3339, until); err != nil {
		return nil, fmt.Errorf("parse previous %s grace deadline: %w", name, err)
	}
	if wrapped {
		value, err = security.DecryptAESGCM(current, value)
		if err != nil {
			return nil, fmt.Errorf("decrypt previous %s: %w", name, err)
		}
	}
	secret, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode previous %s: %w", name, err)
	}
	return secret, nil
}

func resumeInstallationSecretRotation(ctx context.Context, database *db.DB, configDir string) error {
	if !security.PGPKeypairExists(configDir) {
		return nil
	}
	current, err := database.AppSecret(ctx, "installation_secret")
	if err != nil {
		return err
	}
	previous, err := loadPreviousSecret(ctx, database, "installation_secret", current, false)
	if err != nil || len(previous) == 0 {
		return err
	}
	if security.PGPPrivateKeyReadable(configDir, current) {
		return nil
	}
	if !security.PGPPrivateKeyReadable(configDir, previous) {
		return errors.New("PGP private key cannot be decrypted with current or previous installation secret")
	}
	return security.ReencryptPGPPrivateKey(configDir, string(previous), string(current))
}

func reencryptSensitiveRows(ctx context.Context, database *db.DB, previous, current []byte) error {
	if err := reencryptColumn(ctx, database, "api_tokens", "id", "token_enc", previous, current); err != nil {
		return err
	}
	return reencryptSecurityReports(ctx, database, previous, current)
}

type encryptedRow struct{ id, value string }

func reencryptColumn(ctx context.Context, database *db.DB, table, idColumn, valueColumn string, previous, current []byte) error {
	last := ""
	for {
		rows, err := database.Read().QueryContext(ctx, `SELECT `+idColumn+`,`+valueColumn+` FROM `+table+` WHERE `+idColumn+`>? AND `+valueColumn+` IS NOT NULL ORDER BY `+idColumn+` LIMIT 500`, last)
		if err != nil {
			return err
		}
		batch := make([]encryptedRow, 0, 500)
		for rows.Next() {
			var row encryptedRow
			if err := rows.Scan(&row.id, &row.value); err != nil {
				_ = rows.Close()
				return err
			}
			row.value, err = reencryptValue(row.value, previous, current)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("re-encrypt %s row %s: %w", table, row.id, err)
			}
			batch = append(batch, row)
			last = row.id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		if err := database.Write(ctx, func(tx *sql.Tx) error {
			for _, row := range batch {
				if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET `+valueColumn+`=? WHERE `+idColumn+`=?`, []byte(row.value), row.id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("write re-encrypted %s batch: %w", table, err)
		}
		if len(batch) < 500 {
			return nil
		}
	}
}

func reencryptValue(value string, previous, current []byte) (string, error) {
	if _, err := security.DecryptAESGCM(current, value); err == nil {
		return value, nil
	}
	plain, err := security.DecryptAESGCM(previous, value)
	if err != nil {
		return "", err
	}
	return security.EncryptAESGCM(current, plain)
}

type securityReportCipherRow struct{ id, body, algorithm, contact string }

func reencryptSecurityReports(ctx context.Context, database *db.DB, previous, current []byte) error {
	last := ""
	for {
		rows, err := database.Read().QueryContext(ctx, `SELECT tracking_id,body_enc,body_alg,contact_enc FROM security_reports WHERE tracking_id>? ORDER BY tracking_id LIMIT 500`, last)
		if err != nil {
			return err
		}
		batch := make([]securityReportCipherRow, 0, 500)
		for rows.Next() {
			var row securityReportCipherRow
			var contact sql.NullString
			if err := rows.Scan(&row.id, &row.body, &row.algorithm, &contact); err != nil {
				_ = rows.Close()
				return err
			}
			if row.algorithm == "aes-256-gcm" {
				if row.body, err = reencryptValue(row.body, previous, current); err != nil {
					_ = rows.Close()
					return fmt.Errorf("re-encrypt security report %s body: %w", row.id, err)
				}
			} else if row.algorithm != "pgp" {
				_ = rows.Close()
				return fmt.Errorf("security report %s uses unsupported encryption algorithm %q", row.id, row.algorithm)
			}
			if contact.Valid {
				row.contact, err = reencryptValue(contact.String, previous, current)
				if err != nil {
					_ = rows.Close()
					return fmt.Errorf("re-encrypt security report %s contact: %w", row.id, err)
				}
			}
			batch = append(batch, row)
			last = row.id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		if err := database.Write(ctx, func(tx *sql.Tx) error {
			for _, row := range batch {
				var contact any
				if row.contact != "" {
					contact = []byte(row.contact)
				}
				if _, err := tx.ExecContext(ctx, `UPDATE security_reports SET body_enc=?,contact_enc=? WHERE tracking_id=?`, []byte(row.body), contact, row.id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("write re-encrypted security report batch: %w", err)
		}
		if len(batch) < 500 {
			return nil
		}
	}
}

func resumeEncryptionKeyRotation(ctx context.Context, database *db.DB, cfg *config.ServerConfig) error {
	current, err := base64.StdEncoding.DecodeString(cfg.Security.EncryptionKey)
	if err != nil || len(current) != 32 {
		return errors.New("current server.security.encryption_key is invalid")
	}
	previous, err := loadPreviousSecret(ctx, database, "encryption_key", current, true)
	if err != nil || len(previous) == 0 {
		return err
	}
	return reencryptSensitiveRows(ctx, database, previous, current)
}

func writeSecretRotationAudit(ctx context.Context, database *db.DB, cfg *config.ServerConfig, event, operatorIP, reason string) error {
	details := "operator_ip=" + operatorIP + " reason=" + reason
	if _, err := database.ExecResult(ctx, `INSERT INTO audit_log(category,action,details,success) VALUES('security',?,?,1)`, event, details); err != nil {
		return fmt.Errorf("write database audit event: %w", err)
	}
	lgr, err := logger.Open(cfg.GetLogDir())
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer lgr.Close()
	lgr.WriteAudit(logger.AuditEntry{Category: "security", Action: event, ActorIP: operatorIP, Details: details, Success: true})
	return nil
}
