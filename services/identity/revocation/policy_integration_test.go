package revocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func updateSyntheticPolicy(t *testing.T, db *mongo.Database, update bson.D) {
	t.Helper()
	result, err := db.Collection(signerPolicyCollection).UpdateOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}}, update)
	if err != nil || result.ModifiedCount != 1 {
		t.Fatal("cannot change synthetic policy", err)
	}
}

func TestSignedSuspensionRejectsMissingRetiredAndMalformedKeyPolicy(t *testing.T) {
	cases := map[string]func(*testing.T, *mongo.Database){
		"missing": func(t *testing.T, db *mongo.Database) {
			_, err := db.Collection(signerPolicyCollection).DeleteOne(context.Background(),
				bson.D{{Key: "_id", Value: signerPolicyID}})
			if err != nil {
				t.Fatal(err)
			}
		},
		"revoked": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "revoked"}}}})
		},
		"retired": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "retired"}}}})
		},
		"future": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
				{Key: "not_before", Value: time.Now().UTC().Add(time.Hour)},
			}}})
		},
		"expired": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
				{Key: "not_after", Value: time.Now().UTC().Add(-time.Minute)},
			}}})
		},
		"wrong role": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
				{Key: "security_key_sha256", Value: strings.Repeat("0", 64)},
			}}})
		},
		"wrong environment": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
				{Key: "environment", Value: "production"},
			}}})
		},
		"zero generation": func(t *testing.T, db *mongo.Database) {
			updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
				{Key: "generation", Value: int64(0)},
			}}})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			db, r, op, sec := authorizedFixture(t)
			addActiveAccount(t, db, syntheticSubject, 7)
			addSession(t, db, syntheticSubject, 7, 44)
			signed := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("1", 32))
			mutate(t, db)
			if err := r.SuspendAndRevokeApproved(context.Background(), signed); !errors.Is(err, ErrApprovalDenied) {
				t.Fatal("invalid signer policy accepted", err)
			}
			if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
				disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 ||
				journalCount(t, db) != 0 {
				t.Fatal("denied signer policy mutated account/sessions/journal")
			}
		})
	}
}

func TestKeyGenerationRetirementInvalidatesOldApprovalsEvenIfKeysReused(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 55)
	old := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("2", 32))
	updateSyntheticPolicy(t, db, bson.D{{Key: "$inc", Value: bson.D{
		{Key: "generation", Value: int64(1)},
	}}})
	if err := r.SuspendAndRevokeApproved(context.Background(), old); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("old generation survived rotation", err)
	}
	next := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("3", 32))
	next.Approval.PolicyGeneration = 2
	next = signedTestSuspension(t, next.Approval, op, sec)
	if err := r.SuspendAndRevokeApproved(context.Background(), next); err != nil {
		t.Fatal("current generation should be accepted", err)
	}
	var policy struct {
		Generation int64 `bson:"generation"`
		UseFence   int64 `bson:"use_fence"`
	}
	if err := db.Collection(signerPolicyCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}}).Decode(&policy); err != nil {
		t.Fatal(err)
	}
	if policy.Generation != 2 || policy.UseFence != 1 || journalCount(t, db) != 1 {
		t.Fatal("policy generation or write fence did not advance exactly once")
	}
}

func TestKeyRotationFailsClosedForOldProcessAndEnablesFreshPinnedSigners(t *testing.T) {
	db, oldRevoker, oldOperator, oldSecurity := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 66)
	oldSigned := approvedTestCommand(t, oldOperator, oldSecurity, syntheticSubject, 7, strings.Repeat("4", 32))
	newOperator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	newSecurity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	opFingerprint := sha256.Sum256(newOperator.Public().(ed25519.PublicKey))
	securityFingerprint := sha256.Sum256(newSecurity.Public().(ed25519.PublicKey))
	updateSyntheticPolicy(t, db, bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "operator_key_sha256", Value: hex.EncodeToString(opFingerprint[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityFingerprint[:])},
		}},
		{Key: "$inc", Value: bson.D{{Key: "generation", Value: int64(1)}}},
	})
	if err := oldRevoker.SuspendAndRevokeApproved(context.Background(), oldSigned); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("old cached signing keys remained authorized after rotation", err)
	}
	newRevoker, err := NewAuthorizedStagingRevoker(context.Background(), oldRevoker.client,
		newOperator.Public().(ed25519.PublicKey), newSecurity.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	newSigned := approvedTestCommand(t, newOperator, newSecurity, syntheticSubject, 7, strings.Repeat("5", 32))
	newSigned.Approval.PolicyGeneration = 2
	newSigned = signedTestSuspension(t, newSigned.Approval, newOperator, newSecurity)
	if err := newRevoker.SuspendAndRevokeApproved(context.Background(), newSigned); err != nil {
		t.Fatal("fresh pinned signers and generation were denied", err)
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "credential-staged-disabled" ||
		!disabled || version != 8 || sessionCount(t, db, syntheticSubject) != 0 ||
		journalCount(t, db) != 1 {
		t.Fatal("rotated signers did not produce correct atomic suspension")
	}
}

func TestPolicyWriteFenceRollsBackWithFailedSuspension(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 77)
	signed := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("6", 32))
	r.afterAccountWrite = func() error { return errors.New("synthetic rollback") }
	if err := r.SuspendAndRevokeApproved(context.Background(), signed); !errors.Is(err, ErrApprovalStore) {
		t.Fatal("expected rollback after policy write", err)
	}
	var policy struct {
		UseFence int64 `bson:"use_fence"`
	}
	if err := db.Collection(signerPolicyCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}}).Decode(&policy); err != nil {
		t.Fatal(err)
	}
	if policy.UseFence != 0 || journalCount(t, db) != 0 {
		t.Fatal("policy write fence or audit escaped aborted transaction")
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 {
		t.Fatal("account or session escaped aborted transaction")
	}
	r.afterAccountWrite = nil
	if err := r.SuspendAndRevokeApproved(context.Background(), signed); err != nil {
		t.Fatal("retry following rollback should commit", err)
	}
	if err := db.Collection(signerPolicyCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}}).Decode(&policy); err != nil {
		t.Fatal(err)
	}
	if policy.UseFence != 1 {
		t.Fatal("policy fence not committed exactly once")
	}
}
