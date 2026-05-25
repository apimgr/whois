package config

import (
	"errors"
	"path"
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
			continue // Skip empty (from //)
		}
		if err := validatePathSegment(seg); err != nil {
			return err
		}
	}

	return nil
}

// SafePath normalizes and validates - returns error if invalid
func SafePath(input string) (string, error) {
	if err := validatePath(input); err != nil {
		return "", err
	}
	return normalizePath(input), nil
}
