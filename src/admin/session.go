package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/casapps/caswhois/src/db"
)

// Session represents an admin session
type Session struct {
	ID           string
	AdminID      int64
	IPAddress    string
	UserAgent    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
}

// CreateSession creates a new admin session
func CreateSession(ctx context.Context, database *db.DB, adminID int64, ipAddress, userAgent string, duration time.Duration) (*Session, error) {
	// Generate session ID (32 random bytes = 64 hex chars)
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	// Insert session into database
	_, err = database.Server.ExecContext(ctx,
		`INSERT INTO admin_sessions (id, user_id, ip_address, user_agent, created_at, expires_at, last_activity)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sessionID, adminID, ipAddress, userAgent, now, expiresAt, now)

	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}

	session := &Session{
		ID:           sessionID,
		AdminID:      adminID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		LastActivity: now,
	}

	return session, nil
}

// GetSession retrieves a session by ID
func GetSession(ctx context.Context, database *db.DB, sessionID string) (*Session, error) {
	var session Session

	err := database.Server.QueryRowContext(ctx,
		`SELECT id, user_id, ip_address, user_agent, created_at, expires_at, last_activity
		 FROM admin_sessions
		 WHERE id = ?`,
		sessionID).Scan(
		&session.ID,
		&session.AdminID,
		&session.IPAddress,
		&session.UserAgent,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.LastActivity,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}

	return &session, nil
}

// ValidateSession checks if a session is valid and not expired
func ValidateSession(ctx context.Context, database *db.DB, sessionID string) (*Session, error) {
	session, err := GetSession(ctx, database, sessionID)
	if err != nil {
		return nil, err
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		_ = DeleteSession(ctx, database, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// UpdateSessionActivity updates the last activity timestamp
func UpdateSessionActivity(ctx context.Context, database *db.DB, sessionID string) error {
	_, err := database.Server.ExecContext(ctx,
		`UPDATE admin_sessions
		 SET last_activity = ?
		 WHERE id = ?`,
		time.Now(), sessionID)

	if err != nil {
		return fmt.Errorf("update session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout)
func DeleteSession(ctx context.Context, database *db.DB, sessionID string) error {
	_, err := database.Server.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE id = ?`,
		sessionID)

	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}

// DeleteAllAdminSessions deletes all sessions for a specific admin
func DeleteAllAdminSessions(ctx context.Context, database *db.DB, adminID int64) error {
	_, err := database.Server.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE user_id = ?`,
		adminID)

	if err != nil {
		return fmt.Errorf("delete admin sessions: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes all expired sessions
func CleanupExpiredSessions(ctx context.Context, database *db.DB) (int64, error) {
	result, err := database.Server.ExecContext(ctx,
		`DELETE FROM admin_sessions WHERE expires_at < ?`,
		time.Now())

	if err != nil {
		return 0, fmt.Errorf("cleanup expired sessions: %w", err)
	}

	count, _ := result.RowsAffected()
	return count, nil
}

// generateSessionID generates a random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 32 bytes = 64 hex chars
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
