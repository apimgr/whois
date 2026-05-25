package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casapps/caswhois/src/db"
	"github.com/casapps/caswhois/src/security"
)

// Admin represents an admin account
type Admin struct {
	ID           int64
	Email        string
	PasswordHash string
	Name         string
	IsSuper      bool
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLogin    *time.Time
}

// CreateAdminRequest holds data for creating an admin
type CreateAdminRequest struct {
	Email    string
	Password string
	Name     string
	IsSuper  bool
}

// HasAdmins checks if any admin accounts exist
func HasAdmins(ctx context.Context, database *db.DB) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var count int
	var query string

	// Check driver to use correct table name
	if database.Driver == "sqlite" {
		query = "SELECT COUNT(*) FROM admins"
	} else {
		query = "SELECT COUNT(*) FROM usr_admins"
	}

	err := database.Users.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("query admin count: %w", err)
	}

	return count > 0, nil
}

// CreateAdmin creates a new admin account
func CreateAdmin(ctx context.Context, database *db.DB, req CreateAdminRequest) (*Admin, error) {
	// Validate input
	if req.Email == "" {
		return nil, errors.New("email is required")
	}
	if req.Password == "" {
		return nil, errors.New("password is required")
	}
	if len(req.Password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	// Normalize email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Hash password
	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Prepare insert query
	var query string
	if database.Driver == "sqlite" {
		query = `INSERT INTO admins (email, password_hash, name, is_super, is_active, created_at, updated_at)
				 VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				 RETURNING id, created_at, updated_at`
	} else {
		query = `INSERT INTO usr_admins (email, password_hash, name, is_super, is_active, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				 RETURNING id, created_at, updated_at`
	}

	// Insert admin
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	admin := &Admin{
		Email:        req.Email,
		PasswordHash: passwordHash,
		Name:         req.Name,
		IsSuper:      req.IsSuper,
		IsActive:     true,
	}

	var createdAt, updatedAt time.Time
	err = database.Users.QueryRowContext(ctx, query,
		admin.Email, admin.PasswordHash, admin.Name, admin.IsSuper,
	).Scan(&admin.ID, &createdAt, &updatedAt)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			return nil, errors.New("admin with this email already exists")
		}
		return nil, fmt.Errorf("insert admin: %w", err)
	}

	admin.CreatedAt = createdAt
	admin.UpdatedAt = updatedAt

	return admin, nil
}

// GetAdminByEmail retrieves an admin by email
func GetAdminByEmail(ctx context.Context, database *db.DB, email string) (*Admin, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	var query string
	if database.Driver == "sqlite" {
		query = `SELECT id, email, password_hash, name, is_super, is_active, created_at, updated_at, last_login
				 FROM admins WHERE email = ?`
	} else {
		query = `SELECT id, email, password_hash, name, is_super, is_active, created_at, updated_at, last_login
				 FROM usr_admins WHERE email = $1`
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	admin := &Admin{}
	var lastLogin sql.NullTime

	err := database.Users.QueryRowContext(ctx, query, email).Scan(
		&admin.ID, &admin.Email, &admin.PasswordHash, &admin.Name,
		&admin.IsSuper, &admin.IsActive, &admin.CreatedAt, &admin.UpdatedAt, &lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("admin not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query admin: %w", err)
	}

	if lastLogin.Valid {
		admin.LastLogin = &lastLogin.Time
	}

	return admin, nil
}

// GetAdminByID retrieves an admin by ID
func GetAdminByID(ctx context.Context, database *db.DB, id int64) (*Admin, error) {
	var query string
	if database.Driver == "sqlite" {
		query = `SELECT id, email, password_hash, name, is_super, is_active, created_at, updated_at, last_login
				 FROM admins WHERE id = ?`
	} else {
		query = `SELECT id, email, password_hash, name, is_super, is_active, created_at, updated_at, last_login
				 FROM usr_admins WHERE id = $1`
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	admin := &Admin{}
	var lastLogin sql.NullTime

	err := database.Users.QueryRowContext(ctx, query, id).Scan(
		&admin.ID, &admin.Email, &admin.PasswordHash, &admin.Name,
		&admin.IsSuper, &admin.IsActive, &admin.CreatedAt, &admin.UpdatedAt, &lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("admin not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query admin: %w", err)
	}

	if lastLogin.Valid {
		admin.LastLogin = &lastLogin.Time
	}

	return admin, nil
}

// VerifyPassword checks if the password matches the admin's hash
func (a *Admin) VerifyPassword(password string) (bool, error) {
	return security.VerifyPassword(password, a.PasswordHash)
}

// GenerateSetupToken generates a one-time setup token
func GenerateSetupToken() (string, error) {
	// Generate 16 random bytes (32 hex characters)
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// StoreSetupToken stores the setup token in the database
func StoreSetupToken(ctx context.Context, database *db.DB, token string) error {
	// Store setup token in server config table
	var query string
	if database.Driver == "sqlite" {
		query = `INSERT OR REPLACE INTO config (key, value, updated_at, updated_by)
				 VALUES ('setup_token', ?, CURRENT_TIMESTAMP, 'system')`
	} else {
		query = `INSERT INTO srv_config (key, value, updated_at, updated_by)
				 VALUES ('setup_token', $1, CURRENT_TIMESTAMP, 'system')
				 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := database.Server.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("store setup token: %w", err)
	}

	return nil
}

// GetSetupToken retrieves the setup token from the database
func GetSetupToken(ctx context.Context, database *db.DB) (string, error) {
	var query string
	if database.Driver == "sqlite" {
		query = "SELECT value FROM config WHERE key = 'setup_token'"
	} else {
		query = "SELECT value FROM srv_config WHERE key = 'setup_token'"
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var token string
	err := database.Server.QueryRowContext(ctx, query).Scan(&token)
	if err == sql.ErrNoRows {
		return "", errors.New("setup token not found")
	}
	if err != nil {
		return "", fmt.Errorf("query setup token: %w", err)
	}

	return token, nil
}

// InvalidateSetupToken marks the setup token as used
func InvalidateSetupToken(ctx context.Context, database *db.DB) error {
	// Delete the setup token (it's one-time use)
	var query string
	if database.Driver == "sqlite" {
		query = "DELETE FROM config WHERE key = 'setup_token'"
	} else {
		query = "DELETE FROM srv_config WHERE key = 'setup_token'"
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := database.Server.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("invalidate setup token: %w", err)
	}

	return nil
}

// IsFirstRun checks if this is the first run (no admins exist and no setup token)
func IsFirstRun(ctx context.Context, database *db.DB) (bool, error) {
	hasAdmins, err := HasAdmins(ctx, database)
	if err != nil {
		return false, err
	}

	// If admins exist, it's not first run
	if hasAdmins {
		return false, nil
	}

	// Check if setup token exists (setup in progress)
	_, err = GetSetupToken(ctx, database)
	if err == nil {
		// Setup token exists, setup already started
		return false, nil
	}

	// No admins and no setup token = first run
	return true, nil
}

// UpdateAdminProfile updates admin profile information (name, email)
// See AI.md PART 17 for profile management
func UpdateAdminProfile(ctx context.Context, database *db.DB, adminID int64, name, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Validate email
	email = strings.TrimSpace(email)
	if !strings.Contains(email, "@") || len(email) < 3 {
		return errors.New("invalid email address")
	}

	// Validate name
	name = strings.TrimSpace(name)
	if len(name) < 1 {
		return errors.New("name cannot be empty")
	}

	var query string
	if database.Driver == "sqlite" {
		query = "UPDATE admins SET name = ?, email = ?, updated_at = ? WHERE id = ?"
	} else {
		query = "UPDATE usr_admins SET name = $1, email = $2, updated_at = $3 WHERE id = $4"
	}

	_, err := database.Users.ExecContext(ctx, query, name, email, time.Now(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update admin profile: %w", err)
	}

	return nil
}

// UpdateAdminPassword updates admin password with old password verification
// See AI.md PART 17 and PART 11 for password security requirements
func UpdateAdminPassword(ctx context.Context, database *db.DB, adminID int64, oldPassword, newPassword string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Reject passwords with leading/trailing whitespace (AI.md PART 0)
	if strings.TrimSpace(oldPassword) != oldPassword {
		return errors.New("old password contains leading or trailing whitespace")
	}
	if strings.TrimSpace(newPassword) != newPassword {
		return errors.New("new password contains leading or trailing whitespace")
	}

	// Get current admin
	var currentHash string
	var query string
	if database.Driver == "sqlite" {
		query = "SELECT password_hash FROM admins WHERE id = ?"
	} else {
		query = "SELECT password_hash FROM usr_admins WHERE id = $1"
	}

	err := database.Users.QueryRowContext(ctx, query, adminID).Scan(&currentHash)
	if err != nil {
		return fmt.Errorf("failed to get admin: %w", err)
	}

	// Verify old password
	valid, err := security.VerifyPassword(oldPassword, currentHash)
	if err != nil {
		return fmt.Errorf("failed to verify old password: %w", err)
	}
	if !valid {
		return errors.New("old password is incorrect")
	}

	// Validate new password (basic validation, extend as needed)
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	// Hash new password with Argon2id (AI.md PART 11)
	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	if database.Driver == "sqlite" {
		query = "UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?"
	} else {
		query = "UPDATE usr_admins SET password_hash = $1, updated_at = $2 WHERE id = $3"
	}

	_, err = database.Users.ExecContext(ctx, query, newHash, time.Now(), adminID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// GetAdminAPIToken retrieves the admin's API token (returns masked version for display)
// See AI.md PART 17 for API token management
func GetAdminAPIToken(ctx context.Context, database *db.DB, adminID int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var token string
	var query string
	if database.Driver == "sqlite" {
		query = "SELECT token_hash FROM api_tokens WHERE admin_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
	} else {
		query = "SELECT token_hash FROM usr_api_tokens WHERE admin_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1"
	}

	err := database.Users.QueryRowContext(ctx, query, adminID).Scan(&token)
	if err == sql.ErrNoRows {
		return "", nil // No token exists
	}
	if err != nil {
		return "", fmt.Errorf("failed to get API token: %w", err)
	}

	// Return masked version: show first 8 and last 4 characters
	// Token format: adm_<32 chars>
	if len(token) > 12 {
		return token[:8] + "..." + token[len(token)-4:], nil
	}

	return token[:4] + "...", nil
}

// RegenerateAdminAPIToken creates a new API token for the admin and revokes old ones
// See AI.md PART 17 and PART 11 for token requirements
func RegenerateAdminAPIToken(ctx context.Context, database *db.DB, adminID int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Revoke all existing tokens for this admin
	var revokeQuery string
	if database.Driver == "sqlite" {
		revokeQuery = "UPDATE api_tokens SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL"
	} else {
		revokeQuery = "UPDATE usr_api_tokens SET revoked_at = $1 WHERE admin_id = $2 AND revoked_at IS NULL"
	}

	_, err := database.Users.ExecContext(ctx, revokeQuery, time.Now(), adminID)
	if err != nil {
		return "", fmt.Errorf("failed to revoke old tokens: %w", err)
	}

	// Generate new token (AI.md PART 11: 256-bit with prefix)
	plainToken, err := security.GenerateToken("adm")
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Hash token for storage (AI.md PART 11: SHA-256)
	tokenHash := security.HashToken(plainToken)

	// Store token
	var insertQuery string
	if database.Driver == "sqlite" {
		insertQuery = "INSERT INTO api_tokens (admin_id, token_hash, created_at) VALUES (?, ?, ?)"
	} else {
		insertQuery = "INSERT INTO usr_api_tokens (admin_id, token_hash, created_at) VALUES ($1, $2, $3)"
	}

	_, err = database.Users.ExecContext(ctx, insertQuery, adminID, tokenHash, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to store new token: %w", err)
	}

	// Return plain token (shown once, never retrievable again)
	return plainToken, nil
}
