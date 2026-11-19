package production

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	accountTestReplica = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"
	accountTestPass    = "a very strong unique password for prod 2026"
)

func productionReplica(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	uri := os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL")
	if uri == "" {
		t.Skip("Production transaction tests require an ephemeral localhost replica set")
	}
	if uri != accountTestReplica {
		t.Fatal("Refusing external production account test MongoDB")
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
	db := client.Database(Database)
	for _, name := range []string{accountCollectionName, sessionCollectionName} {
		if err := db.Collection(name).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		for _, name := range []string{accountCollectionName, sessionCollectionName} {
			_ = db.Collection(name).Drop(c)
		}
		_ = client.Disconnect(c)
	})
	return client, db
}

func TestProductionAccountLoginSuspensionAndVersionGuard(t *testing.T) {
	client, db := productionReplica(t)
	ctx := context.Background()
	a, err := NewAccountAuthority(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := a.Register(ctx, "matthias", accountTestPass)
	if err != nil || !sessionSubjectPattern.MatchString(subject) {
		t.Fatal("Cannot create isolated native account", err)
	}
	var row struct {
		CredentialHash string `bson:"credential_hash"`
		Environment    string `bson:"environment"`
		Source         string `bson:"source"`
		Version        int64  `bson:"session_version"`
	}
	if err := db.Collection(accountCollectionName).FindOne(ctx,
		bson.D{{Key: "_id", Value: subject}}).Decode(&row); err != nil {
		t.Fatal(err)
	}
	if row.Environment != "production" || row.Source != accountSource ||
		row.Version != 1 || row.CredentialHash == accountTestPass ||
		!password.Verify(accountTestPass, row.CredentialHash) {
		t.Fatal("Production account hash or environment not isolated")
	}
	for _, invalid := range []struct{ alias, password string }{
		{"matthias", "wrong"},
		{"matthias", ""},
		{"unknown", accountTestPass},
		{"Matthias", accountTestPass},
		{"staging.matthias", accountTestPass},
	} {
		handle, err := a.Issue(ctx, invalid.alias, invalid.password)
		if handle != "" || !errors.Is(err, ErrAccountDenied) {
			t.Fatalf("Bad credentials admitted: %q, %v", invalid.alias, err)
		}
	}
	handle, err := a.Issue(ctx, "matthias", accountTestPass)
	if err != nil || !regexp.MustCompile(`^so1_[A-Za-z0-9_-]{43}$`).MatchString(handle) {
		t.Fatal("Legitimate credentials could not create a versioned session", err)
	}
	if name, err := a.Validate(ctx, handle); err != nil || name != subject {
		t.Fatal("Authoritative account version not checked", err)
	}
	if version, eligible, err := a.CurrentSessionVersion(ctx, "production", subject); err != nil || !eligible || version != 1 {
		t.Fatal("Active production version unavailable", err)
	}
	if _, _, err := a.CurrentSessionVersion(ctx, "staging", subject); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Staging environment accepted")
	}
	if err := a.SuspendAndRevoke(ctx, subject); err != nil {
		t.Fatal("Atomic production suspension failed", err)
	}
	if got, err := a.Validate(ctx, handle); got != "" || !errors.Is(err, session.ErrDenied) {
		t.Fatal("Previously issued handle survived suspension", err)
	}
	if newHandle, err := a.Issue(ctx, "matthias", accountTestPass); newHandle != "" || !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Suspended account issued a new session", err)
	}
	if version, eligible, err := a.CurrentSessionVersion(ctx, "production", subject); err != nil || eligible || version != 0 {
		t.Fatal("Suspended account remained eligible", err)
	}
	count, err := db.Collection(sessionCollectionName).CountDocuments(ctx, bson.D{{Key: "subject", Value: subject}})
	if err != nil || count != 0 {
		t.Fatal("Atomic revoke left active session rows", err)
	}
}

func TestProductionAccountsAreNotAliasesForStagingReservations(t *testing.T) {
	client, db := productionReplica(t)
	ctx := context.Background()
	a, err := NewAccountAuthority(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy/staging row with identical alias in the isolated
	// account collection; it must never authorize a production session.
	hash, err := password.HashNew(accountTestPass)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection(accountCollectionName).InsertOne(ctx, bson.D{
		{Key: "_id", Value: alice},
		{Key: "environment", Value: "staging"},
		{Key: "source", Value: "shadowops-identity"},
		{Key: "alias_key", Value: "captain"},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
		{Key: "credential_hash", Value: hash},
		{Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if handle, err := a.Issue(ctx, "captain", accountTestPass); handle != "" || !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Legacy imported alias became a production login")
	}
	subject, err := a.Register(ctx, "captain", accountTestPass)
	if err != nil || subject == alice {
		t.Fatal("Staging alias captured new production identity", err)
	}
	if _, err := a.Register(ctx, "captain", accountTestPass); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Duplicate native account name accepted", err)
	}
}

func TestProductionSuspensionConcurrentWithLoginNeverLeavesAuthorizedSession(t *testing.T) {
	client, db := productionReplica(t)
	ctx := context.Background()
	a, err := NewAccountAuthority(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := a.Register(ctx, "soldier", accountTestPass)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Issue(ctx, "soldier", accountTestPass)
	if err != nil {
		t.Fatal(err)
	}
	const contestants = 4
	handles := make(chan string, contestants)
	begin := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < contestants; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			handle, err := a.Issue(context.Background(), "soldier", accountTestPass)
			if err == nil {
				handles <- handle
			} else if !errors.Is(err, ErrAccountDenied) && !errors.Is(err, ErrAccountStore) {
				t.Errorf("Unexpected concurrent issuance error: %v", err)
			}
		}()
	}
	close(begin)
	// The suspension might lose a transient transaction write conflict;
	// retry with a fresh CAS until it commits or we hit a definite failure.
	var suspended bool
	for n := 0; n < 16; n++ {
		err := a.SuspendAndRevoke(ctx, subject)
		if err == nil {
			suspended = true
			break
		}
		if !errors.Is(err, ErrAccountStore) {
			t.Fatalf("Unexpected suspension result %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	close(handles)
	if !suspended {
		t.Fatal("Could not commit suspension under concurrent login")
	}
	all := []string{first}
	for handle := range handles {
		all = append(all, handle)
	}
	for _, handle := range all {
		if subject, err := a.Validate(ctx, handle); subject != "" || !errors.Is(err, session.ErrDenied) {
			t.Fatal("Stale concurrent login remains authorized", err)
		}
	}
	count, err := db.Collection(sessionCollectionName).CountDocuments(ctx, bson.D{
		{Key: "environment", Value: "production"},
		{Key: "subject", Value: subject},
	})
	if err != nil || count != 0 {
		t.Fatal("Session row survived concurrent revoke", err)
	}
}

func TestProductionAccountRejectsWeakPasswordsInvalidAliasesAndNilDependencies(t *testing.T) {
	if _, err := NewAccountAuthority(nil, nil); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Nil client admitted")
	}
	var authority *AccountAuthority
	if _, err := authority.Register(context.Background(), "matthias", accountTestPass); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Nil authority registered an account")
	}
	if _, err := authority.Issue(context.Background(), "matthias", accountTestPass); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Nil authority issued a session")
	}
	if err := authority.SuspendAndRevoke(context.Background(), alice); !errors.Is(err, ErrAccountDenied) {
		t.Fatal("Nil authority revoked an account")
	}
	for _, s := range []string{"", "short-pass", string([]byte{0xff, 0xfe}), string(make([]byte, 4097))} {
		if validPassword(s) {
			t.Fatal("Weak, invalid UTF-8 or oversized password accepted")
		}
	}
	for _, name := range []string{"", "CAPTAIN", "x", "foreign.name", " leading", "own@domain"} {
		if accountAlias.MatchString(name) {
			t.Fatal("Invalid production account name accepted")
		}
	}
}
