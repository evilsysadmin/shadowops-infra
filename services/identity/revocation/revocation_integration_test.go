package revocation

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/mongostore"
	"github.com/evilsysadmin/shadowops-infra/services/identity/pendingaccounts"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const replicaURL = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"

func replica(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	url := os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL")
	if url == "" {
		t.Skip("disposable Mongo replica set is not configured")
	}
	if url != replicaURL {
		t.Fatal("refusing non-local/non-ephemeral Mongo test URL")
	}
	ctx, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	client, err := mongo.Connect(options.Client().ApplyURI(url))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	database := client.Database(StagingDatabase)
	for _, name := range []string{"pending_accounts", "sessions"} {
		if err := database.Collection(name).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A transaction requires both collections to already exist. The test
	// revoker never receives credentials or touches any non-local instance.
	if _, err := database.Collection("pending_accounts").InsertOne(ctx, bson.D{{Key: "_id", Value: "fixture"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Collection("sessions").InsertOne(ctx, bson.D{{Key: "_id", Value: "fixture"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, name := range []string{"pending_accounts", "sessions"} {
			_ = database.Collection(name).Drop(c)
		}
		_ = client.Disconnect(c)
	})
	return client, database
}

func addActiveAccount(t *testing.T, db *mongo.Database, subject string, version int64) {
	t.Helper()
	_, err := db.Collection("pending_accounts").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false},
		{Key: "session_version", Value: version},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func addSession(t *testing.T, db *mongo.Database, subject string, version int64, digest byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	store, err := mongostore.New(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), session.Record{
		Digest: [32]byte{digest}, Environment: "staging", Subject: subject,
		IssuedAt: now, ExpiresAt: now.Add(session.Lifetime), SessionVersion: version,
	}); err != nil {
		t.Fatal(err)
	}
}

func accountState(t *testing.T, db *mongo.Database, subject string) (string, bool, int64) {
	t.Helper()
	var doc struct {
		State    string `bson:"state"`
		Disabled bool   `bson:"credentials_disabled"`
		Version  int64  `bson:"session_version"`
	}
	if err := db.Collection("pending_accounts").FindOne(context.Background(), bson.D{{Key: "_id", Value: subject}}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.State, doc.Disabled, doc.Version
}

func sessionCount(t *testing.T, db *mongo.Database, subject string) int64 {
	t.Helper()
	count, err := db.Collection("sessions").CountDocuments(context.Background(), bson.D{{Key: "subject", Value: subject}, {Key: "environment", Value: "staging"}})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestTransactionalSuspendAndRevokeCommitAndIsolation(t *testing.T) {
	client, db := replica(t)
	ctx := context.Background()
	other := "22222222-2222-4222-8222-222222222222"
	addActiveAccount(t, db, syntheticSubject, 3)
	addActiveAccount(t, db, other, 8)
	addSession(t, db, syntheticSubject, 3, 1)
	addSession(t, db, syntheticSubject, 3, 2)
	addSession(t, db, other, 8, 3)
	revoker, err := NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.SuspendAndRevoke(ctx, syntheticSubject, 3); err != nil {
		t.Fatal(err)
	}
	state, disabled, version := accountState(t, db, syntheticSubject)
	if state != "credential-staged-disabled" || !disabled || version != 4 {
		t.Fatal("account not suspended atomically", state, disabled, version)
	}
	if got := sessionCount(t, db, syntheticSubject); got != 0 {
		t.Fatal("stale sessions remained after committed suspension", got)
	}
	if state, disabled, version := accountState(t, db, other); state != "active" || disabled || version != 8 {
		t.Fatal("other account changed")
	}
	if got := sessionCount(t, db, other); got != 1 {
		t.Fatal("other user's sessions deleted", got)
	}
	if err := revoker.SuspendAndRevoke(ctx, syntheticSubject, 3); !errors.Is(err, ErrConflict) {
		t.Fatal("replay bumped version", err)
	}
	guard, err := pendingaccounts.NewVersionGuard(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, eligible, err := guard.CurrentSessionVersion(ctx, "staging", syntheticSubject); err != nil || eligible {
		t.Fatal("suspended account is eligible", err)
	}
}

func TestTransactionRollbackRestoresAccountAndSessions(t *testing.T) {
	client, db := replica(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 7)
	r, err := NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("synthetic injected interruption after account update")
	r.afterAccountWrite = func() error { return sentinel }
	if err := r.SuspendAndRevoke(context.Background(), syntheticSubject, 7); !errors.Is(err, sentinel) {
		t.Fatal("transaction failed to abort", err)
	}
	state, disabled, version := accountState(t, db, syntheticSubject)
	if state != "active" || disabled || version != 7 {
		t.Fatal("account update leaked from aborted transaction")
	}
	if got := sessionCount(t, db, syntheticSubject); got != 1 {
		t.Fatal("session changed after aborted transaction")
	}
}

func TestConcurrentSuspendsSingleWinner(t *testing.T) {
	client, db := replica(t)
	addActiveAccount(t, db, syntheticSubject, 1)
	addSession(t, db, syntheticSubject, 1, 3)
	r, err := NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, done := context.WithTimeout(context.Background(), 12*time.Second)
			defer done()
			err := r.SuspendAndRevoke(ctx, syntheticSubject, 1)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected concurrent transaction error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent suspend transactions committed", wins.Load())
	}
	_, disabled, version := accountState(t, db, syntheticSubject)
	if !disabled || version != 2 || sessionCount(t, db, syntheticSubject) != 0 {
		t.Fatal("concurrency left unsafe state")
	}
}

func TestSuspensionRefusesWrongVersionAndBadRequests(t *testing.T) {
	client, db := replica(t)
	addActiveAccount(t, db, syntheticSubject, 5)
	r, err := NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"", "Matthias", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		if err := r.SuspendAndRevoke(context.Background(), subject, 5); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe subject accepted", err)
		}
	}
	if err := r.SuspendAndRevoke(context.Background(), syntheticSubject, 4); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong version accepted", err)
	}
	ctx, done := context.WithCancel(context.Background())
	done()
	if err := r.SuspendAndRevoke(ctx, syntheticSubject, 5); !errors.Is(err, ErrInvalid) {
		t.Fatal("cancelled operation accepted", err)
	}
	state, disabled, version := accountState(t, db, syntheticSubject)
	if state != "active" || disabled || version != 5 {
		t.Fatal("invalid request mutated account")
	}
}
