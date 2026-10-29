package issuance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/pendingaccounts"
	"github.com/evilsysadmin/shadowops-infra/services/identity/revocation"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
)

func stagingValidator(t *testing.T, issuer *Issuer) *session.VersionedValidator {
	t.Helper()
	guard, err := pendingaccounts.NewVersionGuard(issuer.client.Database(stagingDatabase))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := session.NewVersionedValidator("staging", issuer.sessions, guard)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func TestStagingRefreshSingleUseAndExpiry(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	original, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, valid := stagingHandleDigest(original)
	if !valid {
		t.Fatal("issuer handle has invalid format")
	}
	before, exists, err := issuer.sessions.Get(ctx, "staging", oldDigest)
	if err != nil || !exists {
		t.Fatal("issued session not persisted", err)
	}
	rotated, err := issuer.Refresh(ctx, original)
	if err != nil || rotated == "" || rotated == original {
		t.Fatal("valid refresh failed", err)
	}
	if sessionCount(t, db) != 1 {
		t.Fatal("refresh must update the same session, not insert a new one")
	}
	validator := stagingValidator(t, issuer)
	if _, err := validator.Validate(ctx, original); !errors.Is(err, session.ErrDenied) {
		t.Fatal("old handle remained usable", err)
	}
	if _, err := issuer.Refresh(ctx, original); !errors.Is(err, ErrDenied) {
		t.Fatal("replayed handle refreshed again", err)
	}
	if got, err := validator.Validate(ctx, rotated); err != nil || got != alice {
		t.Fatal("rotated handle is not valid for the same account", err)
	}
	newDigest, valid := stagingHandleDigest(rotated)
	if !valid || newDigest == oldDigest {
		t.Fatal("rotated handle reused digest")
	}
	after, exists, err := issuer.sessions.Get(ctx, "staging", newDigest)
	if err != nil || !exists || !after.ExpiresAt.Equal(before.ExpiresAt) ||
		after.SessionVersion != before.SessionVersion || after.Subject != before.Subject {
		t.Fatal("rotation changed absolute expiry, subject, or version", err)
	}
}

func TestStagingRefreshFailsClosedOnBadOrUnboundHandles(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	for _, handle := range []string{"", "so1_!!!", "so1_AAAA", "a" + stagingHandlePrefix} {
		if result, err := issuer.Refresh(ctx, handle); result != "" || !errors.Is(err, ErrDenied) {
			t.Fatal("malformed handle was accepted", err)
		}
	}
	if result, err := issuer.Refresh(nil, "so1_AAAA"); result != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("nil context accepted", err)
	}
	if result, err := (*Issuer)(nil).Refresh(ctx, "so1_AAAA"); result != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("nil issuer accepted", err)
	}
	legacy, digest, err := newStagingHandle()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := issuer.sessions.Create(ctx, session.Record{
		Digest: digest, Environment: "staging", Subject: alice,
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), SessionVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := issuer.Refresh(ctx, legacy); result != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("unversioned session bypassed strict refresh", err)
	}
	if sessionCount(t, db) != 1 {
		t.Fatal("denied refresh created or removed a session")
	}
}

func TestStagingRefreshTransactionRollbackPreservesOldHandle(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	old, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	issuer.afterFence = func() error { return errors.New("synthetic rollback") }
	if handle, err := issuer.Refresh(ctx, old); handle != "" || !errors.Is(err, ErrStore) {
		t.Fatal("failed transaction returned a handle", err)
	}
	if sessionCount(t, db) != 1 {
		t.Fatal("rolled back transaction changed session count")
	}
	if got, err := stagingValidator(t, issuer).Validate(ctx, old); err != nil || got != alice {
		t.Fatal("failed transaction invalidated original handle", err)
	}
	issuer.afterFence = nil
	if handle, err := issuer.Refresh(ctx, old); err != nil || handle == "" {
		t.Fatal("old session could not be retried after rollback", err)
	}
}

func TestStagingRefreshCannotOutliveConcurrentSuspension(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	old, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	suspender, err := revocation.NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	handles := make(chan string, 8)
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			handle, err := issuer.Refresh(c, old)
			if err == nil {
				handles <- handle
			} else if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrStore) {
				t.Errorf("unexpected refresh error: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		for attempt := 0; attempt < 40; attempt++ {
			if err := suspender.SuspendAndRevoke(c, alice, 1); err == nil {
				return
			} else if c.Err() != nil {
				t.Errorf("suspension did not commit: %v", err)
				return
			}
			// A conflicting write may transiently abort a Mongo transaction.
			// Retrying the same expected version cannot undo a suspension.
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("suspension did not commit under refresh contention")
	}()
	close(start)
	wg.Wait()
	close(handles)
	if sessionCount(t, db) != 0 {
		t.Fatal("refresh resurrected a session after suspension")
	}
	validator := stagingValidator(t, issuer)
	if _, err := validator.Validate(ctx, old); !errors.Is(err, session.ErrDenied) {
		t.Fatal("revoked original handle accepted", err)
	}
	for handle := range handles {
		if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrDenied) {
			t.Fatal("refresh handle survived committed suspension", err)
		}
	}
	if handle, err := issuer.Refresh(ctx, old); handle != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("suspended account refreshed again", err)
	}
}
