package pendingaccounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/mongostore"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestMongoVersionGuardRejectsDisabledBumpedAndMalformedAccounts(t *testing.T) {
	client, database := disposableDB(t) // disposable localhost only
	ctx := context.Background()
	if _, err := NewVersionGuard(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil database accepted")
	}
	if _, err := NewVersionGuard(client.Database("shadowops_identity_production")); !errors.Is(err, ErrInvalid) {
		t.Fatal("production database accepted")
	}
	guard, err := NewVersionGuard(database)
	if err != nil { t.Fatal(err) }
	a, b := reviewKeys()
	account, err := NewReviewStore(ctx, database, a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey))
	if err != nil { t.Fatal(err) }
	reservation := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if err := account.ReservePending(ctx, reservation); err != nil { t.Fatal(err) }
	proof := signedReview(t, sampleReview(time.Now().UTC().Truncate(time.Second)), a, b)
	if err := account.ReviewPending(ctx, proof); err != nil { t.Fatal(err) }
	if err := account.StageDisabledCredential(ctx, proof, "synthetic-passphrase-2026"); err != nil { t.Fatal(err) }
	if ver, eligible, err := guard.CurrentSessionVersion(ctx, "staging", chessUUID); err != nil || eligible || ver != 0 {
		t.Fatal("staged credential counted as enabled", err)
	}
	if _, _, err := guard.CurrentSessionVersion(ctx, "production", chessUUID); !errors.Is(err, ErrInvalid) {
		t.Fatal("cross-environment version read accepted")
	}
	if _, _, err := guard.CurrentSessionVersion(ctx, "staging", "Matthias"); !errors.Is(err, ErrInvalid) {
		t.Fatal("username accepted instead of UUID")
	}
	if err := database.Collection("sessions").Drop(ctx); err != nil { t.Fatal(err) }
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = database.Collection("sessions").Drop(c)
	})
	sessions, err := mongostore.New(ctx, database)
	if err != nil { t.Fatal(err) }
	secret := bytes.Repeat([]byte{0x72}, 32)
	handle := "so1_" + base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256(append([]byte("shadowops-session-v1:staging:"), secret...))
	now := time.Now().UTC().Truncate(time.Second)
	rec := session.Record{Digest: digest, Environment: "staging", Subject: chessUUID, IssuedAt: now, ExpiresAt: now.Add(session.Lifetime), SessionVersion: 1}
	if err := sessions.Create(ctx, rec); err != nil { t.Fatal(err) }
	validator, err := session.NewVersionedValidator("staging", sessions, guard)
	if err != nil { t.Fatal(err) }
	if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrDenied) {
		t.Fatal("disabled account session accepted", err)
	}

	// A synthetic active account exists ONLY in this disposable Mongo test.
	// Neither the staging runtime nor pendingaccounts offers activation.
	accounts := database.Collection(collectionName)
	filter := bson.D{{Key: "_id", Value: chessUUID}, {Key: "state", Value: disabledCredentialState}}
	enable := bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}}}}
	r, err := accounts.UpdateOne(ctx, filter, enable)
	if err != nil || r.ModifiedCount != 1 { t.Fatal("test-only active fixture failed", err) }
	if subject, err := validator.Validate(ctx, handle); err != nil || subject != chessUUID {
		t.Fatal("matching session version was denied", err)
	}
	// No refresh may upgrade the stored version of an old token.
	upgrade := rec
	upgrade.Digest = [32]byte{9}
	upgrade.IssuedAt = now.Add(time.Second)
	upgrade.SessionVersion = 2
	if ok, err := sessions.Swap(ctx, "staging", digest, upgrade, now.Add(time.Second)); err != nil || ok {
		t.Fatal("session refresh forged a newer version", err)
	}
	if _, err := accounts.UpdateOne(ctx, bson.D{{Key: "_id", Value: chessUUID}},
		bson.D{{Key: "$inc", Value: bson.D{{Key: "session_version", Value: int64(1)}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrDenied) {
		t.Fatal("old session survived version increment", err)
	}
	if _, err := accounts.UpdateOne(ctx, bson.D{{Key: "_id", Value: chessUUID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "credentials_disabled", Value: true}}}}); err != nil { t.Fatal(err) }
	if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrDenied) {
		t.Fatal("disabled account accepted", err)
	}
	if _, err := accounts.UpdateOne(ctx, bson.D{{Key: "_id", Value: chessUUID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "credentials_disabled", Value: false}, {Key: "session_version", Value: "corrupt"}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrStore) {
		t.Fatal("corrupt authoritative version failed open", err)
	}
}
