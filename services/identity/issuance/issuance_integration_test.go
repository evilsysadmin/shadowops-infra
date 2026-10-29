package issuance

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"github.com/evilsysadmin/shadowops-infra/services/identity/pendingaccounts"
	"github.com/evilsysadmin/shadowops-infra/services/identity/revocation"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const replicaURL = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"
const alice = "11111111-1111-4111-8111-111111111111"
const secret = "correct-synthetic-password-2026"

func replica(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	url := os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL")
	if url == "" {
		t.Skip("ephemeral local Mongo replica set not configured")
	}
	if url != replicaURL {
		t.Fatal("refusing non-local Mongo fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(url))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	db := client.Database(stagingDatabase)
	for _, name := range []string{"pending_accounts", "sessions"} {
		if err := db.Collection(name).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		for _, name := range []string{"pending_accounts", "sessions"} {
			_ = db.Collection(name).Drop(c)
		}
		_ = client.Disconnect(c)
	})
	return client, db
}

func syntheticActive(t *testing.T, db *mongo.Database) {
	t.Helper()
	hash, err := password.HashNew(secret)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection("pending_accounts").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: alice},
		{Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
		{Key: "credential_hash", Value: hash},
		{Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sessionCount(t *testing.T, db *mongo.Database) int64 {
	t.Helper()
	n, err := db.Collection("sessions").CountDocuments(context.Background(),
		bson.D{{Key: "environment", Value: "staging"}, {Key: "subject", Value: alice}})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStagingIssuerValidatesCredentialAndRevocation(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ subject, password string }{
		{alice, "incorrect"}, {"22222222-2222-4222-8222-222222222222", secret},
		{"Matthias", secret}, {alice, ""},
	} {
		if handle, err := issuer.Issue(ctx, test.subject, test.password); handle != "" || !errors.Is(err, ErrDenied) {
			t.Fatal("invalid credentials issued session", err)
		}
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil || len(handle) != 47 || sessionCount(t, db) != 1 {
		t.Fatal("valid credentials could not issue persisted session", err)
	}
	guard, err := pendingaccounts.NewVersionGuard(db)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := session.NewVersionedValidator("staging", issuer.sessions, guard)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := validator.Validate(ctx, handle); err != nil || got != alice {
		t.Fatal("versioned session not validated", err)
	}
	suspender, err := revocation.NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := suspender.SuspendAndRevoke(ctx, alice, 1); err != nil {
		t.Fatal(err)
	}
	if sessionCount(t, db) != 0 {
		t.Fatal("suspension left session rows")
	}
	if _, err := validator.Validate(ctx, handle); !errors.Is(err, session.ErrDenied) {
		t.Fatal("revoked handle accepted", err)
	}
	if handle, err := issuer.Issue(ctx, alice, secret); handle != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("suspended account issued new session", err)
	}
}

func TestCredentialChangesBetweenVerifyAndTransaction(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	next, err := password.HashNew("next-synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	issuer.beforeTransaction = func() error {
		result, err := db.Collection("pending_accounts").UpdateOne(context.Background(),
			bson.D{{Key: "_id", Value: alice}},
			bson.D{
				{Key: "$set", Value: bson.D{{Key: "credential_hash", Value: next}}},
				{Key: "$inc", Value: bson.D{
					{Key: "credential_version", Value: int64(1)},
					{Key: "session_version", Value: int64(1)},
				}},
			})
		if err == nil && result.ModifiedCount != 1 {
			return errors.New("synthetic credential change failed")
		}
		return err
	}
	if h, err := issuer.Issue(context.Background(), alice, secret); h != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("old verified password bypassed CAS", err)
	}
	if sessionCount(t, db) != 0 {
		t.Fatal("stale credential created session row")
	}
	issuer.beforeTransaction = nil
	if h, err := issuer.Issue(context.Background(), alice, "next-synthetic-password"); err != nil || h == "" {
		t.Fatal("new credential/version could not issue session", err)
	}
}

func TestFailureAfterAccountFenceRollsBackBothWrites(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	issuer.afterFence = func() error { return errors.New("synthetic injected error") }
	if h, err := issuer.Issue(context.Background(), alice, secret); h != "" || !errors.Is(err, ErrStore) {
		t.Fatal("failed transaction leaked session", err)
	}
	if sessionCount(t, db) != 0 {
		t.Fatal("failed transaction inserted session")
	}
	var account struct {
		LoginFence int64 `bson:"login_fence"`
	}
	if err := db.Collection("pending_accounts").FindOne(context.Background(),
		bson.D{{Key: "_id", Value: alice}}).Decode(&account); err != nil || account.LoginFence != 0 {
		t.Fatal("failed transaction committed account fence", err)
	}
}

func TestConcurrentIssuanceAndSuspensionLeavesNoSession(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	suspender, err := revocation.NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	handles := make(chan string, 6)
	for n := 0; n < 6; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			h, err := issuer.Issue(ctx, alice, secret)
			if err == nil {
				handles <- h
			} else if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrStore) {
				t.Errorf("unexpected issue result: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		ctx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := suspender.SuspendAndRevoke(ctx, alice, 1); err != nil {
			t.Errorf("concurrent suspension failed: %v", err)
		}
	}()
	close(start)
	wg.Wait()
	close(handles)
	if got := sessionCount(t, db); got != 0 {
		t.Fatalf("revocation race left %d session rows", got)
	}
	guard, err := pendingaccounts.NewVersionGuard(db)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := session.NewVersionedValidator("staging", issuer.sessions, guard)
	if err != nil {
		t.Fatal(err)
	}
	for h := range handles {
		if _, err := validator.Validate(context.Background(), h); !errors.Is(err, session.ErrDenied) {
			t.Fatal("issued handle remained authorized after suspension", err)
		}
	}
}
