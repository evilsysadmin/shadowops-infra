package pendingaccounts

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func reviewedCredentialFixture(t *testing.T) (*Store, context.Context, SignedReview) {
	t.Helper()
	_, database := disposableDB(t)
	ctx := context.Background()
	a, b := reviewKeys()
	store, err := NewReviewStore(ctx, database,
		a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	proof := signedReview(t, sampleReview(time.Now().UTC().Truncate(time.Second)), a, b)
	if err := store.ReviewPending(ctx, proof); err != nil {
		t.Fatal(err)
	}
	return store, ctx, proof
}

func TestCredentialStagingStoresOnlyDisabledArgon2id(t *testing.T) {
	store, ctx, proof := reviewedCredentialFixture(t)
	if err := store.StageDisabledCredential(ctx, proof, "synthetic-passphrase-2026"); err != nil {
		t.Fatal(err)
	}
	if err := store.StageDisabledCredential(ctx, proof, "takeover"); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate staging overwrote password", err)
	}
	var account bson.M
	if err := store.accounts.FindOne(ctx, bson.D{{Key: "_id", Value: chessUUID}}).Decode(&account); err != nil {
		t.Fatal(err)
	}
	hash, ok := account["credential_hash"].(string)
	if !ok || !strings.HasPrefix(hash, "$argon2id$") || !password.Verify("synthetic-passphrase-2026", hash) ||
		password.Verify("takeover", hash) {
		t.Fatal("invalid or overwritten Argon2id hash")
	}
	if account["state"] != disabledCredentialState || account["credentials_disabled"] != true ||
		account["environment"] != "staging" || account["credential_version"] != int64(1) ||
		account["session_version"] != int64(1) {
		t.Fatal("credential version or disabled state missing")
	}
	for _, prohibited := range []string{"active", "is_active", "roles", "permissions", "access_token", "refresh_token"} {
		if _, exists := account[prohibited]; exists {
			t.Fatal("unexpected authentication or authorization field", prohibited)
		}
	}
	if _, exists, err := store.FindPending(ctx, chessUUID); err != nil || exists {
		t.Fatal("staged credentials still count as pending", err)
	}
}

func TestStagingRejectsPendingUnknownUnsignedAndMismatchedAccounts(t *testing.T) {
	_, database := disposableDB(t)
	ctx := context.Background()
	a, b := reviewKeys()
	store, err := NewReviewStore(ctx, database,
		a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReservePending(ctx, Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}); err != nil {
		t.Fatal(err)
	}
	proof := signedReview(t, sampleReview(time.Now().UTC().Truncate(time.Second)), a, b)
	if err := store.StageDisabledCredential(ctx, proof, "secret"); !errors.Is(err, ErrConflict) {
		t.Fatal("pending reservation received credentials", err)
	}
	if err := store.ReviewPending(ctx, proof); err != nil {
		t.Fatal(err)
	}
	plain, err := New(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.StageDisabledCredential(ctx, proof, "secret"); !errors.Is(err, ErrInvalid) {
		t.Fatal("reservation-only store staged a credential", err)
	}
	tampered := proof
	tampered.Statement.Subject = chroniclesUUID
	if err := store.StageDisabledCredential(ctx, tampered, "secret"); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered signed review accepted", err)
	}
	other := proof.Statement
	other.Subject = chroniclesUUID
	if err := store.StageDisabledCredential(ctx, signedReview(t, other, a, b), "secret"); !errors.Is(err, ErrConflict) {
		t.Fatal("valid signature for a different UUID accepted", err)
	}
	for _, invalid := range []string{"", strings.Repeat("x", 4097)} {
		if err := store.StageDisabledCredential(ctx, proof, invalid); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid new password accepted", err)
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := store.StageDisabledCredential(cancelled, proof, "secret"); !errors.Is(err, ErrInvalid) {
		t.Fatal("cancelled staging allowed", err)
	}
}

func TestConcurrentCredentialProvisioningHasOneWinner(t *testing.T) {
	store, ctx, proof := reviewedCredentialFixture(t)
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.StageDisabledCredential(ctx, proof, "synthetic-passphrase")
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected Mongo staging error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent writes produced %d successful password provisions", winners.Load())
	}
}
