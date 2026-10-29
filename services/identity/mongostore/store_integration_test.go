package mongostore

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const alice = "11111111-1111-4111-8111-111111111111"

func db(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	uri := os.Getenv("IDENTITY_MONGO_TEST_URL")
	if uri == "" {
		t.Skip("No disposable local MongoDB configured")
	}
	if uri != "mongodb://127.0.0.1:27017" {
		t.Fatal("Integration tests refuse non-local MongoDB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	database := client.Database(StagingDatabase)
	if err := database.Collection(collectionName).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = database.Collection(collectionName).Drop(c)
		_ = client.Disconnect(c)
	})
	return client, database
}

func TestMongoStagingStoreAtomicRotationAndRevocation(t *testing.T) {
	client, database := db(t)
	ctx := context.Background()
	store, err := New(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, client.Database("shadowops_identity_production")); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("store accepted production database")
	}
	if _, err := New(ctx, client.Database("chess_study")); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("store accepted Chess database")
	}
	indexCursor, err := database.Collection(collectionName).Indexes().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var indexes []bson.M
	if err := indexCursor.All(ctx, &indexes); err != nil {
		t.Fatal(err)
	}
	if len(indexes) != 4 {
		t.Fatalf("expected _id, unique, TTL and subject indexes: %d", len(indexes))
	}

	now := time.Now().UTC().Truncate(time.Second)
	digest := [32]byte{1}
	nextDigest := [32]byte{2}
	rec := session.Record{Digest: digest, Environment: "staging", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err := store.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, rec); err == nil {
		t.Fatal("duplicate digest was accepted")
	}
	if got, exists, err := store.Get(ctx, "staging", digest); err != nil || !exists || got.Subject != alice {
		t.Fatalf("missing record %v %v %v", got, exists, err)
	}
	if _, _, err := store.Get(ctx, "production", digest); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("cross-environment query allowed")
	}

	next := session.Record{Digest: nextDigest, Environment: "staging", Subject: alice, IssuedAt: now.Add(time.Second), ExpiresAt: rec.ExpiresAt}
	updated, err := store.Swap(ctx, "staging", digest, next, now.Add(time.Second))
	if err != nil || !updated {
		t.Fatalf("rotation failed %v %v", updated, err)
	}
	if _, found, _ := store.Get(ctx, "staging", digest); found {
		t.Fatal("old digest remained live")
	}
	if got, found, err := store.Get(ctx, "staging", nextDigest); err != nil || !found || got.ExpiresAt != rec.ExpiresAt {
		t.Fatalf("updated digest invalid: %v %v %v", got, found, err)
	}
	if ok, err := store.Swap(ctx, "staging", digest, next, now.Add(time.Second)); err != nil || ok {
		t.Fatal("replay accepted", err)
	}
	if err := store.DeleteSubject(ctx, "staging", alice); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(ctx, "staging", nextDigest); found {
		t.Fatal("revocation failed")
	}
	if err := store.Delete(ctx, "staging", nextDigest); err != nil {
		t.Fatal("idempotent revocation failed", err)
	}
}

func TestMongoConcurrentCASExactlyOneWinner(t *testing.T) {
	_, database := db(t)
	store, err := New(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	start := session.Record{Digest: [32]byte{7}, Environment: "staging", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(session.Lifetime)}
	if err := store.Create(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	ch := make(chan struct{})
	for i := byte(1); i <= 32; i++ {
		wg.Add(1)
		go func(i byte) {
			defer wg.Done()
			<-ch
			next := session.Record{Digest: [32]byte{i, 4}, Environment: "staging", Subject: alice, IssuedAt: now.Add(time.Second), ExpiresAt: start.ExpiresAt}
			ok, err := store.Swap(context.Background(), "staging", start.Digest, next, now.Add(time.Second))
			if err != nil {
				t.Errorf("CAS failed %v", err)
			} else if ok {
				wins.Add(1)
			}
		}(i)
	}
	close(ch)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent CAS winners", wins.Load())
	}
	if _, exists, _ := store.Get(context.Background(), "staging", start.Digest); exists {
		t.Fatal("old session resurrected")
	}
}

func TestMongoRejectsExpiredSwapAndWrongEnvironment(t *testing.T) {
	_, database := db(t)
	store, err := New(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := session.Record{Digest: [32]byte{11}, Environment: "staging", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(time.Second)}
	if err := store.Create(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := session.Record{Digest: [32]byte{12}, Environment: "staging", Subject: alice, IssuedAt: now.Add(2 * time.Second), ExpiresAt: old.ExpiresAt}
	if ok, err := store.Swap(context.Background(), "staging", old.Digest, next, now.Add(2*time.Second)); err == nil && ok {
		t.Fatal("expired session rotated")
	}
	wrong := next
	wrong.Environment = "production"
	if ok, err := store.Swap(context.Background(), "staging", old.Digest, wrong, now); err == nil && ok {
		t.Fatal("wrong environment rotated")
	}
}
