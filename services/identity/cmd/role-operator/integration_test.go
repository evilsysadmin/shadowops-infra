package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/evilsysadmin/shadowops-infra/services/identity/roles"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommandSignedFlowOnDisposableReplica(t *testing.T) {
	const uri = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"
	if os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL") == "" {
		t.Skip("disposable replica not configured")
	}
	if os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL") != uri {
		t.Fatal("refusing non-local target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := fixture.Database("shadowops_identity_staging")
	names := []string{"admin_role_change_journal", "admin_role_signer_policy", "pending_accounts", "sessions", "staging_cka_tokens"}
	for _, n := range names {
		if err := db.Collection(n).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range names {
			_ = db.Collection(n).Drop(context.Background())
		}
		_ = fixture.Disconnect(context.Background())
	})
	if err := db.CreateCollection(ctx, "admin_role_signer_policy"); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IDENTITY_ROLE_ENVIRONMENT": "staging", "IDENTITY_ROLE_MONGO_URI": "mongodb://test:synthetic@localhost/?tls=true"}
	get := func(k string) string { return env[k] }
	connect := func(string) (*mongo.Client, error) { return mongo.Connect(options.Client().ApplyURI(uri)) }
	encode := func(v any) *bytes.Reader {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(b)
	}
	if err := run(ctx, []string{"schema"}, get, strings.NewReader(""), connect); err != nil {
		t.Fatal(err)
	}
	private := func(s string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed([]byte(strings.Repeat(s, 32))) }
	public := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	a, b, op, sec := private("C"), private("D"), private("A"), private("B")
	env["IDENTITY_ROLE_TRUSTED_KEY_A"], env["IDENTITY_ROLE_TRUSTED_KEY_B"] = public(a), public(b)
	now := time.Now().UTC()
	statement := roles.RoleBootstrapStatement{Environment: "staging", Action: "bootstrap-role-signers", OperatorPublicKey: public(op), SecurityPublicKey: public(sec), NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287", EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	message, err := roles.RoleBootstrapMessage(statement)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := map[string]any{"statement": statement, "authority_a_signature": ed25519.Sign(a, message), "authority_b_signature": ed25519.Sign(b, message), "operator_proof": ed25519.Sign(op, message), "security_proof": ed25519.Sign(sec, message)}
	if err := run(ctx, []string{"bootstrap"}, get, encode(bootstrap), connect); err != nil {
		t.Fatal(err)
	}
	const subject = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	_, err = db.Collection("pending_accounts").InsertOne(ctx, bson.D{{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"}, {Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}, {Key: "session_version", Value: int64(1)}, {Key: "role", Value: "user"}})
	if err != nil {
		t.Fatal(err)
	}
	env["IDENTITY_ROLE_TRUSTED_KEY_A"], env["IDENTITY_ROLE_TRUSTED_KEY_B"] = public(op), public(sec)
	change := roles.RoleChange{Environment: "staging", Action: roles.SetRoleAction, Subject: subject, From: roles.User, To: roles.Admin, ExpectedSessionVersion: 1, PolicyGeneration: 1, ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287", EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("c", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	message, err = roles.ApprovalMessage(change)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"change": change, "operator_signature": ed25519.Sign(op, message), "security_signature": ed25519.Sign(sec, message)}
	if err := run(ctx, []string{"change"}, get, encode(request), connect); err != nil {
		t.Fatal(err)
	}
	var account struct {
		Role    string `bson:"role"`
		Version int64  `bson:"session_version"`
	}
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: subject}}).Decode(&account); err != nil || account.Role != "admin" || account.Version != 2 {
		t.Fatalf("grant failed: %+v %v", account, err)
	}
	if err := run(ctx, []string{"change"}, get, encode(request), connect); err == nil {
		t.Fatal("accepted replay")
	}
}
