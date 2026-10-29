// Package password verifies legacy Chess Studio password hashes during the
// future Identity account migration. It has no account store or login handler.
// All stored hashes are untrusted inputs: bound cost before expensive KDF work.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxPasswordBytes = 4096
	maxEncodedBytes  = 256
	bcryptInputBytes = 72

	// Existing Chess Studio / Python argon2-cffi PasswordHasher parameters.
	argonMemoryKiB = 19456
	argonTime      = 2
	argonLanes     = 1
	argonSaltBytes = 16
	argonHashBytes = 32
)

var ErrInvalidPassword = errors.New("invalid password or unsupported hash")

// Verify compares a candidate against an existing Chess Studio hash. It
// accepts Argon2id, older Argon2i and bcrypt 2a/2b/2y for read compatibility.
// It never silently accepts unsupported formats or unbounded KDF parameters.
func Verify(candidate, encoded string) bool {
	if len(candidate) > maxPasswordBytes || len(encoded) == 0 || len(encoded) > maxEncodedBytes {
		return false
	}
	switch {
	case strings.HasPrefix(encoded, "$argon2"):
		return verifyArgon(candidate, encoded)
	case strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		if len(encoded) != 60 {
			return false
		}
		cost, err := bcrypt.Cost([]byte(encoded))
		if err != nil || cost < 4 || cost > 16 {
			return false
		}
		// The legacy Python bcrypt checker ignores bytes beyond the first
		// 72, including when a UTF-8 rune straddles that boundary.
		secret := []byte(candidate)
		if len(secret) > bcryptInputBytes {
			secret = secret[:bcryptInputBytes]
		}
		return bcrypt.CompareHashAndPassword([]byte(encoded), secret) == nil
	default:
		return false
	}
}

// HashNew creates only Argon2id hashes, byte-for-byte compatible with
// Python's argon2-cffi PHC encoding for the same password and salt.
// Existing bcrypt hashes are never rewritten without an authenticated login.
func HashNew(candidate string) (string, error) {
	if len(candidate) == 0 || len(candidate) > maxPasswordBytes {
		return "", ErrInvalidPassword
	}
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrInvalidPassword
	}
	return encodeArgon2id(candidate, salt), nil
}

func encodeArgon2id(candidate string, salt []byte) string {
	key := argon2.IDKey([]byte(candidate), salt, argonTime, argonMemoryKiB, argonLanes, argonHashBytes)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemoryKiB, argonTime, argonLanes,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func verifyArgon(candidate, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[2] != "v=19" {
		return false
	}
	if parts[1] != "argon2id" && parts[1] != "argon2i" {
		return false
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return false
	}
	var memory, iterations, lanes uint64
	seen := make(map[string]bool, 3)
	for _, field := range fields {
		name, number, ok := strings.Cut(field, "=")
		if !ok || seen[name] || number == "" {
			return false
		}
		seen[name] = true
		value, err := strconv.ParseUint(number, 10, 32)
		if err != nil {
			return false
		}
		switch name {
		case "m":
			memory = value
		case "t":
			iterations = value
		case "p":
			lanes = value
		default:
			return false
		}
	}
	// These conservative bounds are a deliberate authentication DoS defense,
	// not a claim of full compatibility with arbitrary PHC encodings.
	if memory < 8*1024 || memory > 64*1024 || iterations < 1 || iterations > 6 ||
		lanes < 1 || lanes > 4 || memory < 8*lanes {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	var derived []byte
	switch parts[1] {
	case "argon2id":
		derived = argon2.IDKey([]byte(candidate), salt, uint32(iterations), uint32(memory), uint8(lanes), uint32(len(want)))
	case "argon2i":
		derived = argon2.Key([]byte(candidate), salt, uint32(iterations), uint32(memory), uint8(lanes), uint32(len(want)))
	}
	return subtle.ConstantTimeCompare(derived, want) == 1
}
