package security

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestHashPasswordAndVerify covers the primary Argon2id round-trip.
func TestHashPasswordAndVerify(t *testing.T) {
	password := "correct-horse-battery-staple"

	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if encoded == "" {
		t.Fatal("HashPassword returned empty string")
	}

	ok, err := VerifyPassword(password, encoded)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Error("VerifyPassword = false for correct password, want true")
	}
}

// TestHashPasswordFormat verifies the encoded string conforms to the
// $argon2id$v=...$m=...,t=...,p=...$<salt>$<hash> format mandated by PART 11.
func TestHashPasswordFormat(t *testing.T) {
	encoded, err := HashPassword("testpassword")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Errorf("encoded hash does not start with $argon2id$: %q", encoded)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("encoded hash has %d $-separated parts, want 6; full hash: %q", len(parts), encoded)
	}

	if parts[1] != "argon2id" {
		t.Errorf("algorithm = %q, want argon2id", parts[1])
	}

	if !strings.HasPrefix(parts[2], "v=") {
		t.Errorf("version field = %q, want v=<number>", parts[2])
	}

	var mem, tim uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tim, &threads); err != nil {
		t.Errorf("parse params field %q: %v", parts[3], err)
	}
	if mem != Argon2Memory {
		t.Errorf("memory param = %d, want %d", mem, Argon2Memory)
	}
	if tim != Argon2Time {
		t.Errorf("time param = %d, want %d", tim, Argon2Time)
	}
	if threads != Argon2Threads {
		t.Errorf("threads param = %d, want %d", threads, Argon2Threads)
	}

	if _, err := base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		t.Errorf("salt field (parts[4]) is not valid raw base64: %v", err)
	}
	if _, err := base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		t.Errorf("hash field (parts[5]) is not valid raw base64: %v", err)
	}
}

// TestHashPasswordSaltLength verifies the decoded salt is exactly SaltLen bytes.
func TestHashPasswordSaltLength(t *testing.T) {
	encoded, err := HashPassword("salty")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("unexpected part count %d", len(parts))
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("base64 decode salt: %v", err)
	}
	if len(salt) != SaltLen {
		t.Errorf("salt length = %d, want %d", len(salt), SaltLen)
	}
}

// TestHashPasswordKeyLength verifies the decoded hash key is exactly Argon2KeyLen bytes.
func TestHashPasswordKeyLength(t *testing.T) {
	encoded, err := HashPassword("keylength")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("unexpected part count %d", len(parts))
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("base64 decode key: %v", err)
	}
	if len(key) != Argon2KeyLen {
		t.Errorf("key length = %d, want %d", len(key), Argon2KeyLen)
	}
}

// TestHashPasswordUnique verifies two calls produce different encoded strings
// because the salt is randomised on each call.
func TestHashPasswordUnique(t *testing.T) {
	p := "same-password"
	h1, err := HashPassword(p)
	if err != nil {
		t.Fatalf("HashPassword call 1: %v", err)
	}
	h2, err := HashPassword(p)
	if err != nil {
		t.Fatalf("HashPassword call 2: %v", err)
	}
	if h1 == h2 {
		t.Error("two HashPassword calls returned identical encoded strings (salt not random)")
	}
}

// TestHashPasswordEmptyPassword verifies the empty-password guard returns an error.
func TestHashPasswordEmptyPassword(t *testing.T) {
	_, err := HashPassword("")
	if err == nil {
		t.Error("HashPassword(\"\") expected error, got nil")
	}
}

// TestVerifyPasswordWrongPassword confirms a different password is rejected.
func TestVerifyPasswordWrongPassword(t *testing.T) {
	encoded, err := HashPassword("correct")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("wrong", encoded)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Error("VerifyPassword with wrong password = true, want false")
	}
}

// TestVerifyPasswordEmptyInputs verifies error returns for empty arguments.
func TestVerifyPasswordEmptyInputs(t *testing.T) {
	cases := []struct {
		name     string
		password string
		hash     string
	}{
		{name: "empty password", password: "", hash: "$argon2id$v=19$m=65536,t=3,p=4$abc$def"},
		{name: "empty hash", password: "pw", hash: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyPassword(tc.password, tc.hash)
			if err == nil {
				t.Errorf("VerifyPassword(%q, %q) expected error, got nil", tc.password, tc.hash)
			}
		})
	}
}

// TestVerifyPasswordMalformedHash covers various malformed hash strings that
// should produce errors rather than panics.
func TestVerifyPasswordMalformedHash(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{name: "wrong number of parts — too few", hash: "$argon2id$v=19$m=65536,t=3,p=4"},
		{name: "wrong algorithm", hash: "$bcrypt$v=19$m=65536,t=3,p=4$abc$def"},
		{name: "bad version field", hash: "$argon2id$version=bad$m=65536,t=3,p=4$abc$def"},
		{name: "bad params field", hash: "$argon2id$v=19$notparams$abc$def"},
		{name: "non-base64 salt", hash: "$argon2id$v=19$m=65536,t=3,p=4$!!!$def"},
		{name: "non-base64 hash body", hash: "$argon2id$v=19$m=65536,t=3,p=4$YWJj$!!!"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyPassword("password", tc.hash)
			if err == nil {
				t.Errorf("VerifyPassword with hash %q expected error, got nil", tc.hash)
			}
		})
	}
}

// TestVerifyPasswordIdempotent verifies that verifying the same correct
// password multiple times always returns true.
func TestVerifyPasswordIdempotent(t *testing.T) {
	encoded, err := HashPassword("idempotent-pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	for i := 0; i < 3; i++ {
		ok, err := VerifyPassword("idempotent-pw", encoded)
		if err != nil {
			t.Fatalf("VerifyPassword call %d: %v", i+1, err)
		}
		if !ok {
			t.Errorf("VerifyPassword call %d = false, want true", i+1)
		}
	}
}

// TestVerifyPasswordSpecialCharacters verifies passwords with spaces, unicode,
// punctuation, and very large inputs are handled correctly.
func TestVerifyPasswordSpecialCharacters(t *testing.T) {
	cases := []struct {
		name     string
		password string
	}{
		{name: "spaces", password: "hello world"},
		{name: "unicode accents", password: "pässwörd"},
		{name: "emoji", password: "pass🔑word"},
		{name: "null byte", password: "pass\x00word"},
		{name: "long 1000 chars", password: strings.Repeat("a", 1000)},
		{name: "printable ascii specials", password: " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := HashPassword(tc.password)
			if err != nil {
				t.Fatalf("HashPassword: %v", err)
			}
			ok, err := VerifyPassword(tc.password, encoded)
			if err != nil {
				t.Fatalf("VerifyPassword correct: %v", err)
			}
			if !ok {
				t.Error("VerifyPassword returned false for correct password")
			}

			bad, err := VerifyPassword(tc.password+"x", encoded)
			if err != nil {
				t.Fatalf("VerifyPassword wrong: %v", err)
			}
			if bad {
				t.Error("VerifyPassword returned true for wrong password")
			}
		})
	}
}

// TestGenerateToken verifies format, body length, hex encoding, and uniqueness.
func TestGenerateToken(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{name: "tok prefix", prefix: "tok"},
		{name: "adm prefix", prefix: "adm"},
		{name: "usr prefix", prefix: "usr"},
		{name: "single char prefix", prefix: "x"},
		{name: "multi-segment prefix", prefix: "org"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := GenerateToken(tc.prefix)
			if err != nil {
				t.Fatalf("GenerateToken(%q): %v", tc.prefix, err)
			}

			expectedPrefix := tc.prefix + "_"
			if !strings.HasPrefix(token, expectedPrefix) {
				t.Errorf("token %q does not start with expected prefix %q", token, expectedPrefix)
			}

			body := token[len(expectedPrefix):]
			// hex-encoded 32 random bytes = 64 chars
			if len(body) != 64 {
				t.Errorf("token body length = %d, want 64 (hex of 32 bytes)", len(body))
			}

			for i, c := range body {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("token body[%d] = %q is not lowercase hex", i, c)
					break
				}
			}
		})
	}
}

// TestGenerateTokenEmptyPrefix verifies that an empty prefix returns an error.
func TestGenerateTokenEmptyPrefix(t *testing.T) {
	_, err := GenerateToken("")
	if err == nil {
		t.Error("GenerateToken(\"\") expected error, got nil")
	}
}

// TestGenerateTokenUnique verifies that two tokens with the same prefix differ.
func TestGenerateTokenUnique(t *testing.T) {
	t1, err := GenerateToken("tok")
	if err != nil {
		t.Fatalf("GenerateToken call 1: %v", err)
	}
	t2, err := GenerateToken("tok")
	if err != nil {
		t.Fatalf("GenerateToken call 2: %v", err)
	}
	if t1 == t2 {
		t.Error("two GenerateToken calls returned identical tokens (random bytes not unique)")
	}
}

// TestHashToken verifies determinism, output length, and lowercase hex format.
func TestHashToken(t *testing.T) {
	token := "tok_abc123"

	h1 := HashToken(token)
	h2 := HashToken(token)

	if h1 != h2 {
		t.Error("HashToken is not deterministic: two calls on same input differ")
	}

	// SHA-256 produces 32 bytes = 64 hex chars.
	if len(h1) != 64 {
		t.Errorf("HashToken length = %d, want 64", len(h1))
	}

	for i, c := range h1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("HashToken output[%d] = %q is not lowercase hex", i, c)
			break
		}
	}
}

// TestHashTokenDifferentInputs confirms different inputs produce different hashes.
func TestHashTokenDifferentInputs(t *testing.T) {
	cases := []struct {
		a string
		b string
	}{
		{"tok_aaa", "tok_bbb"},
		{"", "x"},
		{"tok_" + strings.Repeat("a", 64), "tok_" + strings.Repeat("b", 64)},
	}

	for _, tc := range cases {
		ha := HashToken(tc.a)
		hb := HashToken(tc.b)
		if ha == hb {
			t.Errorf("HashToken(%q) == HashToken(%q), should differ", tc.a, tc.b)
		}
	}
}

// TestHashTokenEmpty verifies the empty string produces a deterministic non-empty hash.
func TestHashTokenEmpty(t *testing.T) {
	h := HashToken("")
	if len(h) != 64 {
		t.Errorf("HashToken(\"\") length = %d, want 64", len(h))
	}
	if h != HashToken("") {
		t.Error("HashToken(\"\") is not deterministic")
	}
}

// TestVerifyToken covers match, mismatch, and edge-case paths.
func TestVerifyToken(t *testing.T) {
	token := "tok_supersecret1234567890abcdef"
	storedHash := HashToken(token)

	cases := []struct {
		name       string
		token      string
		storedHash string
		want       bool
	}{
		{
			name:       "correct token matches stored hash",
			token:      token,
			storedHash: storedHash,
			want:       true,
		},
		{
			name:       "wrong token rejected",
			token:      "tok_wrongtoken",
			storedHash: storedHash,
			want:       false,
		},
		{
			name:       "empty token rejected against real hash",
			token:      "",
			storedHash: storedHash,
			want:       false,
		},
		{
			name:       "empty stored hash rejected against real token",
			token:      token,
			storedHash: "",
			want:       false,
		},
		{
			// HashToken("") is deterministic; both sides hash the empty string the same way.
			name:       "both empty — hash of empty matches hash of empty",
			token:      "",
			storedHash: HashToken(""),
			want:       true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyToken(tc.token, tc.storedHash)
			if got != tc.want {
				t.Errorf("VerifyToken(%q, %q) = %v, want %v", tc.token, tc.storedHash, got, tc.want)
			}
		})
	}
}

// TestVerifyTokenIdempotent confirms calling VerifyToken multiple times is safe.
func TestVerifyTokenIdempotent(t *testing.T) {
	tok := "tok_idempotent"
	h := HashToken(tok)

	for i := 0; i < 3; i++ {
		if !VerifyToken(tok, h) {
			t.Errorf("VerifyToken attempt %d = false, want true", i+1)
		}
	}
}

// TestVerifyTokenDoesNotMatchRawToken confirms that passing an un-hashed token
// as storedHash is always rejected (security: DB stores only the hash).
func TestVerifyTokenDoesNotMatchRawToken(t *testing.T) {
	tok := "tok_rawcheck"
	if VerifyToken(tok, tok) {
		t.Error("VerifyToken(tok, tok) = true — raw token must not match itself as hash")
	}
}

// TestGenerateRandomString verifies length and non-empty output for various sizes.
func TestGenerateRandomString(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{name: "length 1", length: 1},
		{name: "length 10", length: 10},
		{name: "length 32", length: 32},
		{name: "length 64", length: 64},
		{name: "length 128", length: 128},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := GenerateRandomString(tc.length)
			if err != nil {
				t.Fatalf("GenerateRandomString(%d): %v", tc.length, err)
			}
			if len(s) != tc.length {
				t.Errorf("len = %d, want %d", len(s), tc.length)
			}
		})
	}
}

// TestGenerateRandomStringNonPositiveLength verifies error on invalid lengths.
func TestGenerateRandomStringNonPositiveLength(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{name: "zero", length: 0},
		{name: "negative one", length: -1},
		{name: "large negative", length: -100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateRandomString(tc.length)
			if err == nil {
				t.Errorf("GenerateRandomString(%d) expected error, got nil", tc.length)
			}
		})
	}
}

// TestGenerateRandomStringUnique checks two calls return different strings.
func TestGenerateRandomStringUnique(t *testing.T) {
	s1, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	s2, err := GenerateRandomString(32)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if s1 == s2 {
		t.Error("two GenerateRandomString(32) calls returned identical output")
	}
}

// TestGenerateRandomBytes verifies length and non-nil output for various sizes.
func TestGenerateRandomBytes(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{name: "length 1", length: 1},
		{name: "length 16", length: 16},
		{name: "length 32", length: 32},
		{name: "length 256", length: 256},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := GenerateRandomBytes(tc.length)
			if err != nil {
				t.Fatalf("GenerateRandomBytes(%d): %v", tc.length, err)
			}
			if len(b) != tc.length {
				t.Errorf("len = %d, want %d", len(b), tc.length)
			}
		})
	}
}

// TestGenerateRandomBytesNonPositiveLength verifies error and nil slice on invalid lengths.
func TestGenerateRandomBytesNonPositiveLength(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{name: "zero", length: 0},
		{name: "negative one", length: -1},
		{name: "large negative", length: -9999},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := GenerateRandomBytes(tc.length)
			if err == nil {
				t.Errorf("GenerateRandomBytes(%d) expected error, got nil", tc.length)
			}
			if b != nil {
				t.Errorf("GenerateRandomBytes(%d) returned non-nil bytes on error", tc.length)
			}
		})
	}
}

// TestGenerateRandomBytesUnique verifies consecutive calls produce different byte slices.
func TestGenerateRandomBytesUnique(t *testing.T) {
	b1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	b2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}

	equal := true
	for i := range b1 {
		if b1[i] != b2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("two GenerateRandomBytes(32) calls returned identical byte slices")
	}
}

// TestArgon2Constants verifies the exported constants match the values mandated
// by AI.md PART 11.
func TestArgon2Constants(t *testing.T) {
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{name: "Argon2Time", got: Argon2Time, want: 3},
		{name: "Argon2Memory", got: Argon2Memory, want: 64 * 1024},
		{name: "Argon2Threads", got: uint32(Argon2Threads), want: 4},
		{name: "Argon2KeyLen", got: Argon2KeyLen, want: 32},
		{name: "SaltLen", got: uint32(SaltLen), want: 16},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}
