package production

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
	database := client.Database(Database)
	if err := database.Collection(sessionCollectionName).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = database.Collection(sessionCollectionName).Drop(c)
		_ = client.Disconnect(c)
	})
	return client, database
}

func TestMongoProductionStoreAtomicRotationAndRevocation(t *testing.T) {
	client, database := db(t)
	ctx := context.Background()
	store, err := NewSessionStore(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionStore(ctx, client.Database("shadowops_identity_staging")); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("store accepted staging database")
	}
	if _, err := NewSessionStore(ctx, client.Database("chess_study")); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("store accepted Chess database")
	}
	indexCursor, err := database.Collection(sessionCollectionName).Indexes().List(ctx)
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
	rec := session.Record{Digest: digest, Environment: "production", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), SessionVersion: 3}
	if err := store.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, rec); err == nil {
		t.Fatal("duplicate digest was accepted")
	}
	if got, exists, err := store.Get(ctx, "production", digest); err != nil || !exists || got.Subject != alice {
		t.Fatalf("missing record %v %v %v", got, exists, err)
	}
	if _, _, err := store.Get(ctx, "staging", digest); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("cross-environment query allowed")
	}

	next := session.Record{Digest: nextDigest, Environment: "production", Subject: alice, IssuedAt: now.Add(time.Second), ExpiresAt: rec.ExpiresAt, SessionVersion: rec.SessionVersion}
	updated, err := store.Swap(ctx, "production", digest, next, now.Add(time.Second))
	if err != nil || !updated {
		t.Fatalf("rotation failed %v %v", updated, err)
	}
	if _, found, _ := store.Get(ctx, "production", digest); found {
		t.Fatal("old digest remained live")
	}
	if got, found, err := store.Get(ctx, "production", nextDigest); err != nil || !found || got.ExpiresAt != rec.ExpiresAt {
		t.Fatalf("updated digest invalid: %v %v %v", got, found, err)
	}
	if ok, err := store.Swap(ctx, "production", digest, next, now.Add(time.Second)); err != nil || ok {
		t.Fatal("replay accepted", err)
	}
	if err := store.DeleteSubject(ctx, "production", alice); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := store.Get(ctx, "production", nextDigest); found {
		t.Fatal("revocation failed")
	}
	if err := store.Delete(ctx, "production", nextDigest); err != nil {
		t.Fatal("idempotent revocation failed", err)
	}
}

func TestMongoConcurrentCASExactlyOneWinner(t *testing.T) {
	_, database := db(t)
	store, err := NewSessionStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	start := session.Record{Digest: [32]byte{7}, Environment: "production", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(session.Lifetime), SessionVersion: 3}
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
			next := session.Record{Digest: [32]byte{i, 4}, Environment: "production", Subject: alice, IssuedAt: now.Add(time.Second), ExpiresAt: start.ExpiresAt, SessionVersion: start.SessionVersion}
			ok, err := store.Swap(context.Background(), "production", start.Digest, next, now.Add(time.Second))
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
	if _, exists, _ := store.Get(context.Background(), "production", start.Digest); exists {
		t.Fatal("old session resurrected")
	}
}

func TestMongoRejectsLegacyAndForeignSessionRows(t *testing.T) {
 _,database:=db(t)
 ctx:=context.Background()
 store,err:=NewSessionStore(ctx,database)
 if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC().Truncate(time.Second)
 rec:=session.Record{Digest:[32]byte{52},Environment:"production",Subject:alice,IssuedAt:now,ExpiresAt:now.Add(time.Hour),SessionVersion:0}
 if err:=store.Create(ctx,rec);!errors.Is(err,ErrInvalidStore){t.Fatal("unversioned production session created")}
 rec.SessionVersion=4
 rec.Subject="unknown-username"
 if err:=store.Create(ctx,rec);!errors.Is(err,ErrInvalidStore){t.Fatal("invalid subject created")}
 rec.Subject=alice
 rec.Environment="staging"
 if err:=store.Create(ctx,rec);!errors.Is(err,ErrInvalidStore){t.Fatal("cross environment write admitted")}
 // Simulate an old/corrupt database document inserted out of band. The
 // production reader must not silently accept it as a current session.
 rec.Environment="production"
 _,err=database.Collection(sessionCollectionName).InsertOne(ctx,bson.M{
   "digest": "3400000000000000000000000000000000000000000000000000000000000000",
   "environment":"production","subject":alice,
   "issued_at":now,"expires_at":now.Add(time.Hour),"session_version":int64(0),
 })
 if err!=nil{t.Fatal(err)}
 if _,found,err:=store.Get(ctx,"production",[32]byte{52});err==nil||found{
  t.Fatal("malformed production record passed authoritative store")
 }
 // Foreign record with identical digest must not satisfy a production lookup.
 _,err=database.Collection(sessionCollectionName).InsertOne(ctx,bson.M{
   "digest": "3500000000000000000000000000000000000000000000000000000000000000",
   "environment":"staging","subject":alice,
   "issued_at":now,"expires_at":now.Add(time.Hour),"session_version":int64(4),
 })
 if err!=nil{t.Fatal(err)}
 if _,found,err:=store.Get(ctx,"production",[32]byte{53});err!=nil||found{
  t.Fatal("cross environment row surfaced to production")
 }
}

func TestMongoRejectsExpiredSwapAndWrongEnvironment(t *testing.T) {
	_, database := db(t)
	store, err := NewSessionStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	old := session.Record{Digest: [32]byte{11}, Environment: "production", Subject: alice, IssuedAt: now, ExpiresAt: now.Add(time.Second), SessionVersion: 3}
	if err := store.Create(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	next := session.Record{Digest: [32]byte{12}, Environment: "production", Subject: alice, IssuedAt: now.Add(2 * time.Second), ExpiresAt: old.ExpiresAt, SessionVersion: old.SessionVersion}
	if ok, err := store.Swap(context.Background(), "production", old.Digest, next, now.Add(2*time.Second)); err == nil && ok {
		t.Fatal("expired session rotated")
	}
	wrong := next
	wrong.Environment = "staging"
	if ok, err := store.Swap(context.Background(), "production", old.Digest, wrong, now); err == nil && ok {
		t.Fatal("wrong environment rotated")
	}
}
