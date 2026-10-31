package roles

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

func TestRoleJournalSchemaOwnerPreparesPermanentUniqueIndex(t *testing.T) {
	client, db := roleReplica(t)
	ctx := context.Background()
	// A DBA creates the collection, while a separate schema owner is
	// permitted only to create/list its index.
	if err := db.CreateCollection(ctx, roleJournal); err != nil {
		t.Fatal(err)
	}
	if err := PrepareStagingRoleJournalIndex(ctx, client); err != nil {
		t.Fatal("initial DDL failed", err)
	}
	if err := PrepareStagingRoleJournalIndex(ctx, client); err != nil {
		t.Fatal("idempotent DDL failed", err)
	}
	if err := verifyRoleJournal(ctx, db.Collection(roleJournal)); err != nil {
		t.Fatal("schema did not satisfy offline executor", err)
	}
	op, sec := roleKeys()
	if _, err := NewStagingRoleExecutor(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal("offline role executor rejected prepared schema", err)
	}
	first := bson.D{
		{Key: "_id", Value: "synthetic-first"},
		{Key: "environment", Value: "staging"}, {Key: "action", Value: SetRoleAction},
		{Key: "nonce", Value: "11111111111111111111111111111111"},
	}
	if _, err := db.Collection(roleJournal).InsertOne(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := bson.D{
		{Key: "_id", Value: "synthetic-replay"},
		{Key: "environment", Value: "staging"}, {Key: "action", Value: SetRoleAction},
		{Key: "nonce", Value: "11111111111111111111111111111111"},
	}
	if _, err := db.Collection(roleJournal).InsertOne(ctx, second); !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("same nonce was not rejected by durable unique index: %v", err)
	}
	count, err := db.Collection(roleJournal).CountDocuments(ctx, bson.D{})
	if err != nil || count != 1 {
		t.Fatal("replay created or deleted audit evidence", count, err)
	}
}

func TestRoleJournalSchemaRejectsMissingCollectionAndUnsafeExistingIndex(t *testing.T) {
	t.Run("missing collection", func(t *testing.T) {
		client, db := roleReplica(t)
		if err := PrepareStagingRoleJournalIndex(context.Background(), client); !errors.Is(err, ErrRoleStore) {
			t.Fatal("missing journal collection should be denied", err)
		}
		names, err := db.ListCollectionNames(context.Background(), bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if name == roleJournal {
				t.Fatal("schema owner unexpectedly created missing collection")
			}
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		client, db := roleReplica(t)
		ctx := context.Background()
		if err := db.CreateCollection(ctx, roleJournal); err != nil {
			t.Fatal(err)
		}
		_, err := db.Collection(roleJournal).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    bson.D{{Key: "nonce", Value: int32(1)}},
			Options: options.Index().SetName(roleJournalIndex),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := PrepareStagingRoleJournalIndex(ctx, client); !errors.Is(err, ErrRoleStore) {
			t.Fatal("incorrect nonunique index allowed", err)
		}
		if err := verifyRoleJournal(ctx, db.Collection(roleJournal)); !errors.Is(err, ErrRoleStore) {
			t.Fatal("invalid schema is now accepted", err)
		}
	})
	t.Run("unrelated TTL", func(t *testing.T) {
		client, db := roleReplica(t)
		ctx := context.Background()
		if err := db.CreateCollection(ctx, roleJournal); err != nil {
			t.Fatal(err)
		}
		_, err := db.Collection(roleJournal).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    bson.D{{Key: "executed_at", Value: int32(1)}},
			Options: options.Index().SetName("unsafe_retention").SetExpireAfterSeconds(60),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := PrepareStagingRoleJournalIndex(ctx, client); !errors.Is(err, ErrRoleStore) {
			t.Fatal("TTL audit retention hazard was accepted", err)
		}
		// The refused operation must not even create the required index.
		cursor, err := db.Collection(roleJournal).Indexes().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var entries []struct {
			Name string `bson:"name"`
		}
		if err := cursor.All(ctx, &entries); err != nil {
			t.Fatal(err)
		}
		for _, index := range entries {
			if index.Name == roleJournalIndex {
				t.Fatal("schema owner mutated journal before rejecting unsafe TTL")
			}
		}
	})
}

func TestRoleJournalSchemaRejectsInvalidContextOrClient(t *testing.T) {
	if err := PrepareStagingRoleJournalIndex(nil, nil); !errors.Is(err, ErrRoleStore) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := PrepareStagingRoleJournalIndex(ctx, nil); !errors.Is(err, ErrRoleStore) {
		t.Fatal("cancelled context accepted", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := PrepareStagingRoleJournalIndex(ctx, nil); !errors.Is(err, ErrRoleStore) {
		t.Fatal("nil client accepted", err)
	}
}
