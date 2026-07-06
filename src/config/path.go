package config

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ErrPathTraversal = errors.New("path traversal attempt detected")
	ErrInvalidPath   = errors.New("invalid path characters")
	ErrPathTooLong   = errors.New("path exceeds maximum length")

	// Valid path segment: lowercase alphanumeric, hyphens, underscores
	validPathSegment = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

// normalizePath cleans a path for safe use
// - Strips leading/trailing slashes
// - Collapses multiple slashes (// → /)
// - Removes path traversal (.., .)
// - Returns empty string for invalid input
func normalizePath(input string) string {
	if input == "" {
		return ""
	}

	// Use path.Clean to handle .., ., and //
	cleaned := path.Clean(input)

	// Strip leading/trailing slashes
	cleaned = strings.Trim(cleaned, "/")

	// Reject if still contains .. after cleaning (shouldn't happen, but be safe)
	if strings.Contains(cleaned, "..") {
		return ""
	}

	return cleaned
}

// validatePathSegment checks a single path segment (e.g., "admin" in "/admin/dashboard")
func validatePathSegment(segment string) error {
	if segment == "" {
		return ErrInvalidPath
	}
	if len(segment) > 64 {
		return ErrPathTooLong
	}
	if !validPathSegment.MatchString(segment) {
		return ErrInvalidPath
	}
	if segment == "." || segment == ".." {
		return ErrPathTraversal
	}
	return nil
}

// validatePath checks an entire path
func validatePath(p string) error {
	if len(p) > 2048 {
		return ErrPathTooLong
	}

	// Check for traversal attempts before normalization
	if strings.Contains(p, "..") {
		return ErrPathTraversal
	}

	// Check each segment
	segments := strings.Split(strings.Trim(p, "/"), "/")
	for _, seg := range segments {
		if seg == "" {
			// Skip empty (from //)
		continue
		}
		if err := validatePathSegment(seg); err != nil {
			return err
		}
	}

	return nil
}

// SafePath normalizes and validates a user-supplied path value (e.g., from config or API).
// Returns the cleaned path and an error if the path contains traversal, invalid characters,
// or exceeds the maximum length. NOT intended for validating raw HTTP request paths —
// use PathSecurityMiddleware for that purpose.
func SafePath(input string) (string, error) {
	if err := validatePath(input); err != nil {
		return "", err
	}
	return normalizePath(input), nil
}

// SafeFilePath validates that a user-supplied relative path stays within baseDir.
// It runs SafePath on userPath, joins with baseDir, resolves both to absolute paths,
// and rejects any result that escapes baseDir (path traversal guard).
func SafeFilePath(baseDir, userPath string) (string, error) {
	safe, err := SafePath(userPath)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(baseDir, safe)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	if absPath != absBase && !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
		return "", ErrPathTraversal
	}
	return absPath, nil
}
