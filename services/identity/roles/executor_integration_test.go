package roles

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const roleReplicaURL = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"

func roleReplica(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	if os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL") == "" {
		t.Skip("disposable localhost Mongo replica not configured")
	}
	if os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL") != roleReplicaURL {
		t.Fatal("refusing non-local Mongo target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(roleReplicaURL))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	db := client.Database(roleDatabase)
	names := []string{"pending_accounts", "sessions", "staging_cka_tokens", roleJournal, rolePolicy}
	for _, name := range names {
		if err := db.Collection(name).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		finish, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		for _, name := range names {
			_ = db.Collection(name).Drop(finish)
		}
		_ = client.Disconnect(finish)
	})
	return client, db
}

func roleKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat("A", 32))),
		ed25519.NewKeyFromSeed([]byte(strings.Repeat("B", 32)))
}

func roleFixture(t *testing.T) (*mongo.Database, *StagingRoleExecutor, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	client, db := roleReplica(t)
	ctx := context.Background()
	_, err := db.Collection(roleJournal).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: roleJournalKeys(), Options: options.Index().SetName(roleJournalIndex).SetUnique(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	op, sec := roleKeys()
	opHash := sha256.Sum256(op.Public().(ed25519.PublicKey))
	secHash := sha256.Sum256(sec.Public().(ed25519.PublicKey))
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err = db.Collection(rolePolicy).InsertOne(ctx, bson.D{
		{Key: "_id", Value: rolePolicyID},
		{Key: "environment", Value: "staging"}, {Key: "action", Value: SetRoleAction},
		{Key: "state", Value: "active"}, {Key: "generation", Value: int64(1)},
		{Key: "operator_key_sha256", Value: hex.EncodeToString(opHash[:])},
		{Key: "security_key_sha256", Value: hex.EncodeToString(secHash[:])},
		{Key: "not_before", Value: now.Add(-time.Hour)},
		{Key: "not_after", Value: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewStagingRoleExecutor(ctx, client, op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return db, r, op, sec
}

func signRoleChange(t *testing.T, op, sec ed25519.PrivateKey, change RoleChange) SignedRoleChange {
	t.Helper()
	message, err := ApprovalMessage(change)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRoleChange{
		Change: change, OperatorSignature: ed25519.Sign(op, message),
		SecuritySignature: ed25519.Sign(sec, message),
	}
}

func roleAccount(t *testing.T, db *mongo.Database, subject string, version int64, role any) {
	t.Helper()
	doc := bson.D{
		{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false},
		{Key: "session_version", Value: version},
	}
	if role != nil {
		doc = append(doc, bson.E{Key: "role", Value: role})
	}
	if _, err := db.Collection("pending_accounts").InsertOne(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
}

func roleState(t *testing.T, db *mongo.Database, subject string) (string, int64) {
	t.Helper()
	var state struct {
		Role    string `bson:"role"`
		Version int64  `bson:"session_version"`
	}
	if err := db.Collection("pending_accounts").FindOne(context.Background(),
		bson.D{{Key: "_id", Value: subject}}).Decode(&state); err != nil {
		t.Fatal(err)
	}
	return state.Role, state.Version
}

func TestApprovedRoleChangeCommitsAuditRevokesSessionsAndTokens(t *testing.T) {
	db, editor, op, sec := roleFixture(t)
	const owner = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	roleAccount(t, db, owner, 7, nil) // Legacy missing role == user.
	roleAccount(t, db, other, 2, "user")
	_, err := db.Collection("sessions").InsertMany(context.Background(), []any{
		bson.D{{Key: "_id", Value: "owner-session"}, {Key: "environment", Value: "staging"}, {Key: "subject", Value: owner}},
		bson.D{{Key: "_id", Value: "other-session"}, {Key: "environment", Value: "staging"}, {Key: "subject", Value: other}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection("staging_cka_tokens").InsertMany(context.Background(), []any{
		bson.D{{Key: "_id", Value: "owner-token"}, {Key: "subject", Value: owner}, {Key: "active", Value: true}},
		bson.D{{Key: "_id", Value: "other-token"}, {Key: "subject", Value: other}, {Key: "active", Value: true}},
	})
	if err != nil {
		t.Fatal(err)
	}

	change := roleChangeFixture(time.Now().UTC())
	change.Subject, change.ExpectedSessionVersion, change.PolicyGeneration = owner, 7, 1
	signed := signRoleChange(t, op, sec, change)
	if err := editor.ApplyApprovedRoleChange(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	if role, version := roleState(t, db, owner); role != "admin" || version != 8 {
		t.Fatalf("role/version not changed: %s/%d", role, version)
	}
	if role, version := roleState(t, db, other); role != "user" || version != 2 {
		t.Fatal("changed an unrelated account")
	}
	for _, tc := range []struct {
		col, subject string
		want         int64
	}{
		{"sessions", owner, 0}, {"sessions", other, 1},
	} {
		n, err := db.Collection(tc.col).CountDocuments(context.Background(), bson.D{{Key: "subject", Value: tc.subject}})
		if err != nil || n != tc.want {
			t.Fatal("unexpected surviving session", tc, n, err)
		}
	}
	for _, tc := range []struct {
		subject string
		want    int64
	}{{owner, 0}, {other, 1}} {
		n, err := db.Collection("staging_cka_tokens").CountDocuments(context.Background(),
			bson.D{{Key: "subject", Value: tc.subject}, {Key: "active", Value: true}})
		if err != nil || n != tc.want {
			t.Fatal("unexpected active token", tc, n, err)
		}
	}
	var audit struct {
		From           string `bson:"from"`
		To             string `bson:"to"`
		Subject        string `bson:"subject"`
		ApprovalSHA256 string `bson:"approval_sha256"`
		OperatorSHA256 string `bson:"operator_key_sha256"`
		SecuritySHA256 string `bson:"security_key_sha256"`
	}
	if err := db.Collection(roleJournal).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: "staging:set-role:" + change.Nonce}}).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if audit.From != "user" || audit.To != "admin" || audit.Subject != owner ||
		len(audit.ApprovalSHA256) != 64 || len(audit.OperatorSHA256) != 64 ||
		len(audit.SecuritySHA256) != 64 || audit.OperatorSHA256 == audit.SecuritySHA256 {
		t.Fatal("role audit incomplete")
	}
	if err := editor.ApplyApprovedRoleChange(context.Background(), signed); !errors.Is(err, ErrRoleConflict) {
		t.Fatal("replay accepted", err)
	}
	// The same nonce must never authorize a *different* account either.
	roleAccount(t, db, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", 4, "user")
	fresh := roleChangeFixture(time.Now().UTC())
	fresh.Subject, fresh.ExpectedSessionVersion, fresh.PolicyGeneration = "cccccccc-cccc-4ccc-8ccc-cccccccccccc", 4, 1
	fresh.Nonce = change.Nonce
	if err := editor.ApplyApprovedRoleChange(context.Background(), signRoleChange(t, op, sec, fresh)); !errors.Is(err, ErrRoleConflict) {
		t.Fatal("nonce reused across subjects", err)
	}
	if role, version := roleState(t, db, fresh.Subject); role != "user" || version != 4 {
		t.Fatal("cross-subject replay changed account")
	}
	// Admin -> user is an explicitly signed downgrade; do not allow stale
	// signed transition from earlier session version.
	downgrade := roleChangeFixture(time.Now().UTC())
	downgrade.From, downgrade.To = Admin, User
	downgrade.Subject, downgrade.ExpectedSessionVersion, downgrade.PolicyGeneration = owner, 8, 1
	downgrade.Nonce = strings.Repeat("e", 32)
	if err := editor.ApplyApprovedRoleChange(context.Background(), signRoleChange(t, op, sec, downgrade)); err != nil {
		t.Fatal(err)
	}
	if role, version := roleState(t, db, owner); role != "user" || version != 9 {
		t.Fatal("downgrade failed")
	}
}

func TestRoleChangeFailsClosedAndRollsBackWithoutApprovedPolicy(t *testing.T) {
	db, editor, op, sec := roleFixture(t)
	owner := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	roleAccount(t, db, owner, 7, "user")
	change := roleChangeFixture(time.Now().UTC())
	change.Subject, change.ExpectedSessionVersion, change.PolicyGeneration = owner, 7, 1
	signed := signRoleChange(t, op, sec, change)
	// With a valid signature but a retired policy the account must stay USER.
	_, err := db.Collection(rolePolicy).UpdateOne(context.Background(),
		bson.D{{Key: "_id", Value: rolePolicyID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "retired"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.ApplyApprovedRoleChange(context.Background(), signed); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("retired signer policy accepted", err)
	}
	if role, version := roleState(t, db, owner); role != "user" || version != 7 {
		t.Fatal("failed authorization mutated account")
	}
	_, _ = db.Collection(rolePolicy).UpdateOne(context.Background(),
		bson.D{{Key: "_id", Value: rolePolicyID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "active"}}}})
	// An injected failure after the role write must undo the entire transaction.
	editor.afterAccountWrite = func() error { return errors.New("synthetic write failure") }
	if err := editor.ApplyApprovedRoleChange(context.Background(), signed); !errors.Is(err, ErrRoleStore) {
		t.Fatal("failed operation reported success", err)
	}
	if role, version := roleState(t, db, owner); role != "user" || version != 7 {
		t.Fatal("partial role write committed")
	}
	n, err := db.Collection(roleJournal).CountDocuments(context.Background(), bson.D{})
	if err != nil || n != 0 {
		t.Fatal("failed operation inserted audit")
	}
	editor.afterAccountWrite = nil
	// A completely unknown stored role (not legacy missing) is not user.
	_, _ = db.Collection("pending_accounts").UpdateOne(context.Background(),
		bson.D{{Key: "_id", Value: owner}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "role", Value: "root"}}}})
	if err := editor.ApplyApprovedRoleChange(context.Background(), signed); !errors.Is(err, ErrRoleConflict) {
		t.Fatal("unknown stored role promoted", err)
	}
}

func TestRoleExecutorNeedsPreexistingPermanentUniqueJournal(t *testing.T) {
	client, db := roleReplica(t)
	op, sec := roleKeys()
	_, err := NewStagingRoleExecutor(context.Background(), client, op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if !errors.Is(err, ErrRoleStore) {
		t.Fatal("missing unique journal accepted", err)
	}
	_, err = db.Collection(roleJournal).Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: roleJournalKeys(), Options: options.Index().SetName(roleJournalIndex).SetUnique(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	// MongoDB refuses TTL on compound indexes. Add an independent TTL
	// index instead: ANY expiring audit index must block this executor.
	_, err = db.Collection(roleJournal).Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{{Key: "executed_at", Value: int32(1)}},
		Options: options.Index().SetName("unsafe_audit_ttl").SetExpireAfterSeconds(60),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewStagingRoleExecutor(context.Background(), client, op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if !errors.Is(err, ErrRoleStore) {
		t.Fatal("TTL audit index accepted", err)
	}
}
