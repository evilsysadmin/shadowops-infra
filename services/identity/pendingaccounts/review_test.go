package pendingaccounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func reviewKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
}

func signedReview(t *testing.T, v ReviewStatement, a, b ed25519.PrivateKey) SignedReview {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(reviewDomain), payload...)
	return SignedReview{
		Statement: v,
		SignatureA: ed25519.Sign(a, message),
		SignatureB: ed25519.Sign(b, message),
	}
}

func sampleReview(now time.Time) ReviewStatement {
	evidence := sha256.Sum256([]byte("synthetic offline ownership dossier"))
	return ReviewStatement{
		Environment: "staging",
		Subject: chessUUID,
		Source: "chess-studio",
		LegacyUsername: "Matthias",
		ReviewRef: reviewURL,
		EvidenceSHA256: hex.EncodeToString(evidence[:]),
		Nonce: "00112233445566778899aabbccddeeff",
		ReviewedAt: now.Unix(),
		ValidUntil: now.Add(5 * time.Minute).Unix(),
	}
}

func TestSignedReviewRequiresTwoDistinctTrustedReviewers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, b := reviewKeys()
	first := a.Public().(ed25519.PublicKey)
	second := b.Public().(ed25519.PublicKey)
	statement := sampleReview(now)
	good := signedReview(t, statement, a, b)
	if err := VerifyReview(good, first, second, now); err != nil {
		t.Fatal(err)
	}
	// A signature on the original statement cannot attest modified facts.
	for name, change := range map[string]func(*ReviewStatement){
		"other-environment": func(v *ReviewStatement) { v.Environment = "production" },
		"other-subject": func(v *ReviewStatement) { v.Subject = chroniclesUUID },
		"other-product": func(v *ReviewStatement) { v.Source = "chronicles" },
		"other-username": func(v *ReviewStatement) { v.LegacyUsername = "Other" },
		"other-review": func(v *ReviewStatement) { v.ReviewRef = "https://github.com/evilsysadmin/shadowops-infra/issues/288" },
		"other-evidence": func(v *ReviewStatement) { v.EvidenceSHA256 = hex.EncodeToString(bytes.Repeat([]byte{0x41}, 32)) },
		"other-nonce": func(v *ReviewStatement) { v.Nonce = "ffeeddccbbaa99887766554433221100" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := good
			change(&tampered.Statement)
			if VerifyReview(tampered, first, second, now) == nil {
				t.Fatal("valid signatures accepted modified ownership facts")
			}
		})
	}
	for _, pair := range [][2]ed25519.PublicKey{{first, first}, {second, first}, {nil, second}} {
		if VerifyReview(good, pair[0], pair[1], now) == nil {
			t.Fatal("review accepted missing, duplicated or swapped trust anchors")
		}
	}
	lone := good
	lone.SignatureB = append([]byte(nil), good.SignatureA...)
	if VerifyReview(lone, first, second, now) == nil {
		t.Fatal("one signer could satisfy two reviewers")
	}
	wrongSig := signedReview(t, statement, b, a)
	if VerifyReview(wrongSig, first, second, now) == nil {
		t.Fatal("reviewer identity was not pinned")
	}
}

func TestSignedReviewRejectsExpiredUnboundedOrMalformedProofs(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, b := reviewKeys()
	first, second := a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey)
	base := sampleReview(now)
	for name, change := range map[string]func(*ReviewStatement){
		"expired": func(v *ReviewStatement) { v.ReviewedAt = now.Add(-20 * time.Minute).Unix(); v.ValidUntil = now.Add(-10 * time.Minute).Unix() },
		"unbounded": func(v *ReviewStatement) { v.ValidUntil = now.Add(24 * time.Hour).Unix() },
		"future-review": func(v *ReviewStatement) { v.ReviewedAt = now.Add(10 * time.Minute).Unix(); v.ValidUntil = now.Add(11 * time.Minute).Unix() },
		"wrong-issuer": func(v *ReviewStatement) { v.Environment = "production" },
		"missing-evidence": func(v *ReviewStatement) { v.EvidenceSHA256 = "" },
		"uppercase-digest": func(v *ReviewStatement) { v.EvidenceSHA256 = "ABCDEF" + v.EvidenceSHA256[6:] },
		"missing-nonce": func(v *ReviewStatement) { v.Nonce = "" },
		"non-uuid": func(v *ReviewStatement) { v.Subject = "Matthias" },
		"non-review-url": func(v *ReviewStatement) { v.ReviewRef = "https://example.com/287" },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			change(&v)
			proof := signedReview(t, v, a, b)
			if VerifyReview(proof, first, second, now) == nil {
				t.Fatal("invalid attestation was accepted even with valid signatures")
			}
		})
	}
	good := signedReview(t, base, a, b)
	if VerifyReview(good, first, second, now.Add(6*time.Minute)) == nil {
		t.Fatal("expired attestation accepted")
	}
	if VerifyReview(good, first, second, time.Time{}) == nil {
		t.Fatal("zero clock accepted")
	}
}

func TestMongoReviewNeedsPinnedKeysAndPreservesInactiveState(t *testing.T) {
	client, db := disposableDB(t)
	ctx := context.Background()
	a, b := reviewKeys()
	one, two := a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey)
	if _, err := NewReviewStore(ctx, nil, one, two); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing database was accepted")
	}
	if _, err := NewReviewStore(ctx, client.Database("shadowops_identity_production"), one, two); !errors.Is(err, ErrInvalid) {
		t.Fatal("production database was accepted")
	}
	if _, err := NewReviewStore(ctx, db, one, one); !errors.Is(err, ErrInvalid) {
		t.Fatal("one signer was accepted as two")
	}
	store, err := NewReviewStore(ctx, db, one, two)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	reservation := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	statement := sampleReview(time.Now().UTC().Truncate(time.Second))
	proof := signedReview(t, statement, a, b)
	if !errors.Is(plain.ReviewPending(ctx, proof), ErrInvalid) {
		t.Fatal("default pending store allowed review without pinned authorities")
	}
	// Another valid signature on a different source account does not bypass
	// the conditional Mongo filter, even when both authorities signed it.
	wrong := statement
	wrong.Source = "chronicles"
	if err := store.ReviewPending(ctx, signedReview(t, wrong, a, b)); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong source was able to review reservation", err)
	}
	wrong = statement
	wrong.LegacyUsername = "Other"
	if err := store.ReviewPending(ctx, signedReview(t, wrong, a, b)); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong username was able to review reservation", err)
	}
	if err := store.ReviewPending(ctx, proof); err != nil {
		t.Fatal(err)
	}
	if err := store.ReviewPending(ctx, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("replayed proof was accepted", err)
	}
	if _, found, err := store.FindPending(ctx, chessUUID); err != nil || found {
		t.Fatal("reviewed reservation remained pending", err)
	}
	var doc bson.M
	if err := db.Collection(collectionName).FindOne(ctx, bson.D{{Key: "_id", Value: chessUUID}}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["state"] != reviewedState || doc["environment"] != "staging" || doc["review_nonce"] != statement.Nonce {
		t.Fatal("review state was not atomically recorded")
	}
	for _, forbidden := range []string{"password_hash", "email", "roles", "is_active", "session_version", "reviewer_private_key"} {
		if _, exists := doc[forbidden]; exists {
			t.Fatal("review stored active authentication material", forbidden)
		}
	}
	// Keeping the second account pending illustrates no implicit cross-app
	// merge even when both products have the same username.
	other := Reservation{Subject: chroniclesUUID, Source: "chronicles", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.FindPending(ctx, chroniclesUUID); err != nil || !found {
		t.Fatal("second product was implicitly activated or merged", err)
	}
}

func TestMongoSimultaneousReviewHasOneWinner(t *testing.T) {
	_, db := disposableDB(t)
	ctx := context.Background()
	a, b := reviewKeys()
	store, err := NewReviewStore(ctx, db, a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReservePending(ctx, Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}); err != nil {
		t.Fatal(err)
	}
	proof := signedReview(t, sampleReview(time.Now().UTC().Truncate(time.Second)), a, b)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := store.ReviewPending(ctx, proof)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected Mongo review error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("Mongo accepted %d concurrent review transitions", wins.Load())
	}
}
