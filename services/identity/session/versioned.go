package session

import "context"

// AccountVersionReader must consult authoritative account state for every
// validation. Missing/disabled accounts return eligible=false.
type AccountVersionReader interface {
	CurrentSessionVersion(ctx context.Context, environment, subject string) (version int64, eligible bool, err error)
}

// VersionedValidator is deliberately read-only: no issuing or refreshing
// versioned sessions before audited login and revocation are implemented.
type VersionedValidator struct {
	manager  *Manager
	accounts AccountVersionReader
}

func NewVersionedValidator(environment string, store Store, accounts AccountVersionReader) (*VersionedValidator, error) {
	if accounts == nil {
		return nil, ErrDenied
	}
	manager, err := NewManager(environment, store)
	if err != nil {
		return nil, err
	}
	return &VersionedValidator{manager: manager, accounts: accounts}, nil
}

func (v *VersionedValidator) Validate(ctx context.Context, handle string) (string, error) {
	if v == nil || v.manager == nil || v.accounts == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrDenied
	}
	rec, err := v.manager.validatedRecord(ctx, handle)
	if err != nil {
		return "", err
	}
	if rec.SessionVersion <= 0 {
		return "", ErrDenied
	}
	version, eligible, err := v.accounts.CurrentSessionVersion(ctx, v.manager.environment, rec.Subject)
	if err != nil {
		return "", ErrStore
	}
	if !eligible || version <= 0 || version != rec.SessionVersion {
		return "", ErrDenied
	}
	return rec.Subject, nil
}
