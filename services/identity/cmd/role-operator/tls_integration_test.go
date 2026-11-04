package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/roles"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestAuthenticatedTLSRoleCommand(t *testing.T) {
	schemaURI := os.Getenv("ROLE_TEST_SCHEMA_URI")
	if schemaURI == "" {
		t.Skip("disposable TLS replica not configured")
	}
	bootstrapURI, executorURI, adminURI := os.Getenv("ROLE_TEST_BOOTSTRAP_URI"), os.Getenv("ROLE_TEST_EXECUTOR_URI"), os.Getenv("IDENTITY_RUNTIME_ADMIN_URI")
	// The test can write to Mongo as its synthetic root fixture; reject all
	// non-local connections before creating the client or running the command.
	for _, entry := range []struct{ uri, user string }{{schemaURI, "role_test_schema"}, {bootstrapURI, "role_test_bootstrap"}, {executorURI, "role_test_executor"}, {adminURI, "identity_root"}} {
		u, err := url.Parse(entry.uri)
		if err != nil || u.Host != "127.0.0.1:27019" || u.User == nil || u.User.Username() != entry.user || u.Query().Get("replicaSet") != "identity-runtime-rs" || u.Query().Get("tls") != "true" {
			t.Fatal("refusing non-disposable fixture target")
		}
	}
	ca := os.Getenv("IDENTITY_RUNTIME_MONGO_CA_FILE")
	if !strings.HasPrefix(ca, "/tmp/identity-runtime-ci-") {
		t.Fatal("refusing non-fixture CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := mongo.Connect(options.Client().ApplyURI(adminURI + "&tlsCAFile=" + url.QueryEscape(ca)))
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	defer root.Disconnect(context.Background())
	binary := filepath.Join(t.TempDir(), "role-operator")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s", out)
	}
	invoke := func(action, uri, keyA, keyB string, request any) error {
		t.Helper()
		var input bytes.Buffer
		if request != nil {
			if err := json.NewEncoder(&input).Encode(request); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(ctx, binary, action)
		cmd.Stdin = &input
		cmd.Env = append(os.Environ(), "IDENTITY_ROLE_ENVIRONMENT=staging", "IDENTITY_ROLE_MONGO_URI="+uri, "IDENTITY_ROLE_TRUSTED_KEY_A="+keyA, "IDENTITY_ROLE_TRUSTED_KEY_B="+keyB)
		output, err := cmd.CombinedOutput()
		if bytes.Contains(output, []byte("synthetic-secret-should-not-appear")) {
			t.Fatal("credential leaked")
		}
		return err
	}
	badCredentials, err := url.Parse(schemaURI)
	if err != nil {
		t.Fatal("fixture URI")
	}
	badCredentials.User = url.UserPassword("role_test_schema", "synthetic-secret-should-not-appear")
	if err := invoke("schema", badCredentials.String(), "", "", nil); err == nil {
		t.Fatal("accepted incorrect credentials")
	}
	if err := invoke("schema", schemaURI, "", "", nil); err != nil {
		t.Fatal("schema operation failed")
	}
	private := func(s string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed([]byte(strings.Repeat(s, 32))) }
	public := func(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
	a, b, op, sec := private("C"), private("D"), private("A"), private("B")
	now := time.Now().UTC()
	statement := roles.RoleBootstrapStatement{Environment: "staging", Action: "bootstrap-role-signers", OperatorPublicKey: public(op), SecurityPublicKey: public(sec), NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287", EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(4 * time.Minute).Unix()}
	message, err := roles.RoleBootstrapMessage(statement)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := map[string]any{"statement": statement, "authority_a_signature": ed25519.Sign(a, message), "authority_b_signature": ed25519.Sign(b, message), "operator_proof": ed25519.Sign(op, message), "security_proof": ed25519.Sign(sec, message)}
	if err := invoke("bootstrap", schemaURI, public(a), public(b), bootstrap); err == nil {
		t.Fatal("schema principal bootstrapped policy")
	}
	if err := invoke("bootstrap", bootstrapURI, public(a), public(b), bootstrap); err != nil {
		t.Fatal("bootstrap operation failed")
	}
	const subject = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	db := root.Database("shadowops_identity_staging")
	_, err = db.Collection("pending_accounts").InsertOne(ctx, bson.D{{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"}, {Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}, {Key: "session_version", Value: int64(1)}, {Key: "role", Value: "user"}})
	if err != nil {
		t.Fatal("fixture account setup failed")
	}
	change := roles.RoleChange{Environment: "staging", Action: roles.SetRoleAction, Subject: subject, From: roles.User, To: roles.Admin, ExpectedSessionVersion: 1, PolicyGeneration: 1, ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287", EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("c", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(4 * time.Minute).Unix()}
	message, err = roles.ApprovalMessage(change)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"change": change, "operator_signature": ed25519.Sign(op, message), "security_signature": ed25519.Sign(sec, message)}
	if err := invoke("change", bootstrapURI, public(op), public(sec), request); err == nil {
		t.Fatal("bootstrap principal changed role")
	}
	if err := invoke("change", executorURI, public(op), public(sec), request); err != nil {
		t.Fatal("role operation failed")
	}
	var account struct {
		Role    string `bson:"role"`
		Version int64  `bson:"session_version"`
	}
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: subject}}).Decode(&account); err != nil || account.Role != "admin" || account.Version != 2 {
		t.Fatal("role transaction did not commit")
	}
	if err := invoke("change", executorURI, public(op), public(sec), request); err == nil {
		t.Fatal("accepted replay")
	}
}
