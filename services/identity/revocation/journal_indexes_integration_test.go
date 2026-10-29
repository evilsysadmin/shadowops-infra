package revocation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestAdministrativeJournalIndexPreparationAndReadOnlyConstructors(t *testing.T) {
	client, db := replica(t)
	ctx := context.Background()
	for _, spec := range administrativeJournals {
		if err := db.Collection(spec.collection).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, spec := range administrativeJournals {
			_ = db.Collection(spec.collection).Drop(c)
		}
	})
	op, sec := approvalTestKeys()
	govA, govB := policyRetirementKeys()

	// Neither constructor is allowed to initialize the collection/index.
	if _, err := NewAuthorizedStagingRevoker(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey)); !errors.Is(err, ErrApprovalStore) {
		t.Fatal("revoker created an unprepared audit journal", err)
	}
	if _, err := NewStagingPolicyRetirer(ctx, client,
		govA.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRetirementStore) {
		t.Fatal("governance created an unprepared audit journal", err)
	}
	names, err := db.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range administrativeJournals {
		for _, name := range names {
			if name == spec.collection {
				t.Fatal("read-only constructor unexpectedly created collection", name)
			}
		}
	}
	if err := PrepareStagingAdministrativeIndexes(ctx, client); err != nil {
		t.Fatal("offline maintenance rejected empty schema", err)
	}
	if err := PrepareStagingAdministrativeIndexes(ctx, client); err != nil {
		t.Fatal("repeated maintenance with same indexes should be idempotent", err)
	}
	if _, err := NewAuthorizedStagingRevoker(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal("preprovisioned suspension audit rejected", err)
	}
	if _, err := NewStagingPolicyRetirer(ctx, client,
		govA.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal("preprovisioned governance audit rejected", err)
	}
}

func TestAdministrativeJournalIndexCheckFailsClosedOnNonUniqueAndTTL(t *testing.T) {
	client, db := replica(t)
	ctx := context.Background()
	for _, spec := range administrativeJournals {
		if err := db.Collection(spec.collection).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, spec := range administrativeJournals {
			_ = db.Collection(spec.collection).Drop(c)
		}
	})
	op, sec := approvalTestKeys()
	govA, govB := policyRetirementKeys()
	suspension := db.Collection(suspensionJournalCollection)
	_, err := suspension.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: requiredJournalKeys(),
		Options: options.Index().SetName("staging_action_nonce_unique"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthorizedStagingRevoker(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey)); !errors.Is(err, ErrApprovalStore) {
		t.Fatal("non-unique replay index accepted", err)
	}
	if err := suspension.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := PrepareStagingAdministrativeIndexes(ctx, client); err != nil {
		t.Fatal(err)
	}
	_, err = suspension.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "executed_at", Value: 1}},
		Options: options.Index().SetName("unsafe_audit_ttl").SetExpireAfterSeconds(3600),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthorizedStagingRevoker(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey)); !errors.Is(err, ErrApprovalStore) {
		t.Fatal("journal with TTL accepted", err)
	}
	if err := PrepareStagingAdministrativeIndexes(ctx, client); !errors.Is(err, ErrAuditIndexNotReady) {
		t.Fatal("maintenance allowed destructive TTL index", err)
	}
	if err := db.Collection(retirementJournalCollection).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	governance := db.Collection(retirementJournalCollection)
	_, err = governance.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: requiredJournalKeys(),
		Options: options.Index().SetName("policy_retirement_nonce_unique").SetUnique(true).SetSparse(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStagingPolicyRetirer(ctx, client,
		govA.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRetirementStore) {
		t.Fatal("sparse policy event index accepted", err)
	}
}
