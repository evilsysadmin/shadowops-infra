// Package session defines the isolated, durable-store-backed lifecycle contract
// for future ShadowOps Identity sessions. It does not authenticate users, hold
// passwords, expose HTTP routes, or create sessions for real accounts.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"time"
)

const (
	// Lifetime is an absolute, non-sliding cap. Rotation cannot extend it.
	Lifetime = 24 * time.Hour
	tokenPrefix = "so1_"
)

var (
	ErrDenied = errors.New("identity session denied")
	ErrStore = errors.New("identity session storage failure")
	subjectPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// Record stores only a digest of a high-entropy opaque handle; a raw
// browser-facing session handle must never appear in a database or log.
// RevokeSubject must be called after password and account changes.
type Record struct {
	Digest [32]byte
	Environment string
	Subject string
	IssuedAt time.Time
	ExpiresAt time.Time
	// SessionVersion is immutable for a session. Zero is legacy/unbound and
	// is always rejected by the strict VersionedValidator.
	SessionVersion int64
}

// Store is a contract for a future persistent backend. Swap MUST be a single
// transactional compare-and-swap across processes: if old is removed/expired,
// it MUST NOT insert next. A memory store is unsuitable for deployed auth.
type Store interface {
	Create(ctx context.Context, record Record) error
	Get(ctx context.Context, environment string, digest [32]byte) (Record, bool, error)
	Swap(ctx context.Context, environment string, oldDigest [32]byte, next Record, now time.Time) (bool, error)
	Delete(ctx context.Context, environment string, digest [32]byte) error
	DeleteSubject(ctx context.Context, environment, subject string) error
}

type Manager struct {
	environment string
	store Store
	clock func() time.Time
}

// NewManager does NOT authenticate the subject. The calling backend must
// successfully validate user credentials BEFORE calling Issue.
func NewManager(environment string, store Store) (*Manager, error) {
	if (environment != "staging" && environment != "production") || store == nil {
		return nil, ErrDenied
	}
	return &Manager{environment: environment, store: store, clock: time.Now}, nil
}

func validSubject(subject string) bool { return subjectPattern.MatchString(subject) }

func (m *Manager) digest(handle string) ([32]byte, bool) {
	var zero [32]byte
	if len(handle) != len(tokenPrefix)+43 || handle[:len(tokenPrefix)] != tokenPrefix {
		return zero, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(handle[len(tokenPrefix):])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != handle[len(tokenPrefix):] {
		return zero, false
	}
	// Prevent staging handles being accepted by production even if a future
	// database driver accidentally shared physical backing storage.
	input := append([]byte("shadowops-session-v1:"+m.environment+":"), raw...)
	return sha256.Sum256(input), true
}

func (m *Manager) newHandle() (string, [32]byte, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", [32]byte{}, ErrDenied
	}
	handle := tokenPrefix + base64.RawURLEncoding.EncodeToString(secret[:])
	digest, ok := m.digest(handle)
	if !ok {
		return "", [32]byte{}, ErrDenied
	}
	return handle, digest, nil
}

func (m *Manager) Issue(ctx context.Context, subject string) (string, error) {
	if m == nil || !validSubject(subject) || ctx.Err() != nil {
		return "", ErrDenied
	}
	handle, digest, err := m.newHandle()
	if err != nil {
		return "", err
	}
	now := m.clock().UTC()
	rec := Record{Digest: digest, Environment: m.environment, Subject: subject, IssuedAt: now, ExpiresAt: now.Add(Lifetime)}
	if err := m.store.Create(ctx, rec); err != nil {
		return "", ErrStore
	}
	return handle, nil
}

// Validate checks only the opaque session and its expiration; it MUST NOT be
// used for user authorization without VersionedValidator's account guard.
func (m *Manager) Validate(ctx context.Context, handle string) (string, error) {
 rec, err := m.validatedRecord(ctx, handle)
 if err != nil { return "", err }
 // Never let the legacy storage-only API bypass account-version checks.
 if rec.SessionVersion > 0 { return "", ErrDenied }
 return rec.Subject, nil
}

func (m *Manager) validatedRecord(ctx context.Context, handle string) (Record, error) {
	if m == nil || ctx == nil || ctx.Err() != nil {
		return Record{}, ErrDenied
	}
	digest, ok := m.digest(handle)
	if !ok {
		return Record{}, ErrDenied
	}
	rec, exists, err := m.store.Get(ctx, m.environment, digest)
	if err != nil {
		return Record{}, ErrStore
	}
	now := m.clock().UTC()
	if !exists || rec.Digest != digest || rec.Environment != m.environment || !validSubject(rec.Subject) ||
		rec.IssuedAt.After(now.Add(30*time.Second)) || !rec.IssuedAt.Before(rec.ExpiresAt) ||
		rec.ExpiresAt.Sub(rec.IssuedAt) > Lifetime || !now.Before(rec.ExpiresAt) {
		return Record{}, ErrDenied
	}
	return rec, nil
}

// Rotate invalidates the old handle and creates a new one with the SAME
// absolute expiry. Atomic Store.Swap makes concurrent refresh single-use.
func (m *Manager) Rotate(ctx context.Context, handle string) (string, error) {
	if m == nil || ctx.Err() != nil {
		return "", ErrDenied
	}
	oldDigest, ok := m.digest(handle)
	if !ok {
		return "", ErrDenied
	}
	rec, exists, err := m.store.Get(ctx, m.environment, oldDigest)
	if err != nil {
		return "", ErrStore
	}
	now := m.clock().UTC()
	if !exists || rec.Digest != oldDigest || rec.Environment != m.environment || !validSubject(rec.Subject) ||
		rec.IssuedAt.After(now.Add(30*time.Second)) || !rec.IssuedAt.Before(rec.ExpiresAt) ||
		rec.ExpiresAt.Sub(rec.IssuedAt) > Lifetime || !now.Before(rec.ExpiresAt) {
		return "", ErrDenied
	}
	// Versioned sessions have no ordinary rotation pathway without a fresh
	// authoritative account-state check and an atomic version-bound design.
	if rec.SessionVersion > 0 { return "", ErrDenied }
	nextHandle, nextDigest, err := m.newHandle()
	if err != nil {
		return "", err
	}
	next := Record{Digest: nextDigest, Environment: m.environment, Subject: rec.Subject, IssuedAt: now, ExpiresAt: rec.ExpiresAt, SessionVersion: rec.SessionVersion}
	swapped, err := m.store.Swap(ctx, m.environment, oldDigest, next, now)
	if err != nil {
		return "", ErrStore
	}
	if !swapped {
		return "", ErrDenied
	}
	return nextHandle, nil
}

// Revocation reports store errors instead of silently pretending success.
// No login, password-change or account-delete handler is wired to this yet.
func (m *Manager) Revoke(ctx context.Context, handle string) error {
	if m == nil || ctx.Err() != nil {
		return ErrDenied
	}
	digest, ok := m.digest(handle)
	if !ok {
		return ErrDenied
	}
	if err := m.store.Delete(ctx, m.environment, digest); err != nil {
		return ErrStore
	}
	return nil
}

func (m *Manager) RevokeSubject(ctx context.Context, subject string) error {
	if m == nil || !validSubject(subject) || ctx.Err() != nil {
		return ErrDenied
	}
	if err := m.store.DeleteSubject(ctx, m.environment, subject); err != nil {
		return ErrStore
	}
	return nil
}
