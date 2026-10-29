package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

type syntheticAccountReader struct {
	version  int64
	eligible bool
	err      error
}

func (r *syntheticAccountReader) CurrentSessionVersion(_ context.Context, _, _ string) (int64, bool, error) {
	return r.version, r.eligible, r.err
}

func TestVersionedValidatorRejectsOldSessionAndChangedAccounts(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	store := newTestStore()
	issuer := manager(t, "staging", store, &now)
	handle, err := issuer.Issue(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	reader := &syntheticAccountReader{version: 1, eligible: true}
	strict, err := NewVersionedValidator("staging", store, reader)
	if err != nil {
		t.Fatal(err)
	}
	strict.manager.clock = func() time.Time { return now }
	if _, err := strict.Validate(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("legacy/unversioned session was accepted", err)
	}
	digest, _ := issuer.digest(handle)
	store.mu.Lock()
	record := store.items[digest]
	record.SessionVersion = 1
	store.items[digest] = record
	store.mu.Unlock()
	if subject, err := strict.Validate(ctx, handle); err != nil || subject != alice {
		t.Fatal("matching versioned session denied", err)
	}
	if _, err := issuer.Validate(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("plain validator bypassed versioned account guard", err)
	}
	if _, err := issuer.Rotate(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("plain rotation bypassed account guard", err)
	}
	reader.version = 2
	if _, err := strict.Validate(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("stale version accepted", err)
	}
	reader.version = 1
	reader.eligible = false
	if _, err := strict.Validate(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("disabled account accepted", err)
	}
	reader.eligible = true
	reader.err = errors.New("synthetic outage")
	if _, err := strict.Validate(ctx, handle); !errors.Is(err, ErrStore) {
		t.Fatal("account store error not failed closed", err)
	}
	if _, err := NewVersionedValidator("staging", store, nil); !errors.Is(err, ErrDenied) {
		t.Fatal("missing account reader accepted")
	}
	if _, err := NewVersionedValidator("typo", store, reader); !errors.Is(err, ErrDenied) {
		t.Fatal("unknown environment accepted")
	}
}
