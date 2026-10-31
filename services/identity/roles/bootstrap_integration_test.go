package roles

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func roleBootstrapAuthorities() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat("C", 32))),
		ed25519.NewKeyFromSeed([]byte(strings.Repeat("D", 32)))
}

func roleBootstrapStatement(now time.Time, operator, security ed25519.PrivateKey) RoleBootstrapStatement {
	return RoleBootstrapStatement{
		Environment: "staging",
		Action: roleBootstrapAction,
		OperatorPublicKey: hex.EncodeToString(operator.Public().(ed25519.PublicKey)),
		SecurityPublicKey: hex.EncodeToString(security.Public().(ed25519.PublicKey)),
		NotBefore: now.Unix(),
		NotAfter: now.Add(48 * time.Hour).Unix(),
		ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287",
		EvidenceSHA256: strings.Repeat("a", 64),
		Nonce: strings.Repeat("b", 32),
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func signRoleBootstrap(t *testing.T, statement RoleBootstrapStatement,
	authorityA, authorityB, operator, security ed25519.PrivateKey) SignedRoleBootstrap {
	t.Helper()
	message, err := RoleBootstrapMessage(statement)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRoleBootstrap{
		Statement: statement,
		AuthorityASignature: ed25519.Sign(authorityA, message),
		AuthorityBSignature: ed25519.Sign(authorityB, message),
		OperatorProof: ed25519.Sign(operator, message),
		SecurityProof: ed25519.Sign(security, message),
	}
}

func roleBootstrapFixture(t *testing.T) (*mongo.Database, *StagingRoleBootstrapper, SignedRoleBootstrap) {
	t.Helper()
	client, db := roleReplica(t)
	ctx := context.Background()
	if err := PrepareStagingRoleJournalIndex(ctx, client); err != nil {
		t.Fatal("offline journal schema", err)
	}
	if err := db.CreateCollection(ctx, rolePolicy); err != nil {
		t.Fatal(err)
	}
	authorityA, authorityB := roleBootstrapAuthorities()
	bootstrapper, err := NewStagingRoleBootstrapper(ctx, client,
		authorityA.Public().(ed25519.PublicKey), authorityB.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	operator, security := roleKeys()
	signed := signRoleBootstrap(t, roleBootstrapStatement(time.Now().UTC(),
		operator, security), authorityA, authorityB, operator, security)
	return db, bootstrapper, signed
}

func TestRoleSignerGenesisIsOneTimeAndEnablesSignedRoleChanges(t *testing.T) {
	db, bootstrap, signed := roleBootstrapFixture(t)
	const subject = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	roleAccount(t, db, subject, 7, User)
	if err := bootstrap.Bootstrap(context.Background(), signed); err != nil {
		t.Fatal("first role signer bootstrap failed", err)
	}
	var policy struct {
		Environment string `bson:"environment"`
		Action string `bson:"action"`
		State string `bson:"state"`
		Generation int64 `bson:"generation"`
		OperatorKeySHA256 string `bson:"operator_key_sha256"`
		SecurityKeySHA256 string `bson:"security_key_sha256"`
	}
	err := db.Collection(rolePolicy).FindOne(context.Background(), bson.D{{Key: "_id", Value: rolePolicyID}}).Decode(&policy)
	if err != nil || policy.Environment != "staging" || policy.Action != SetRoleAction ||
		policy.State != "active" || policy.Generation != 1 ||
		len(policy.OperatorKeySHA256) != 64 || len(policy.SecurityKeySHA256) != 64 ||
		policy.OperatorKeySHA256 == policy.SecurityKeySHA256 {
		t.Fatal("incorrect role policy genesis", err, policy)
	}
	var genesis struct {
		Action string `bson:"action"`
		Nonce string `bson:"nonce"`
		ApprovalSHA256 string `bson:"approval_sha256"`
		AuthorityA string `bson:"authority_a_sha256"`
		AuthorityB string `bson:"authority_b_sha256"`
	}
	err = db.Collection(roleJournal).FindOne(context.Background(), bson.D{{Key: "_id", Value: roleBootstrapGenesisID}}).Decode(&genesis)
	if err != nil || genesis.Action != roleBootstrapAction || genesis.Nonce != signed.Statement.Nonce ||
		len(genesis.ApprovalSHA256) != 64 || len(genesis.AuthorityA) != 64 ||
		len(genesis.AuthorityB) != 64 || genesis.AuthorityA == genesis.AuthorityB {
		t.Fatal("incomplete, missing or unsafe genesis audit", err, genesis)
	}
	if role, version := roleState(t, db, subject); role != "user" || version != 7 {
		t.Fatal("bootstrap must never grant roles or revoke sessions")
	}
	if err := bootstrap.Bootstrap(context.Background(), signed); !errors.Is(err, ErrRoleBootstrapConflict) {
		t.Fatal("replayed role genesis was accepted", err)
	}
	authorityA, authorityB := roleBootstrapAuthorities()
	operator, security := roleKeys()
	fresh := roleBootstrapStatement(time.Now().UTC(), operator, security)
	fresh.Nonce = strings.Repeat("c", 32)
	if err := bootstrap.Bootstrap(context.Background(),
		signRoleBootstrap(t, fresh, authorityA, authorityB, operator, security)); !errors.Is(err, ErrRoleBootstrapConflict) {
		t.Fatal("new nonce re-created original role signer policy", err)
	}
	editor, err := NewStagingRoleExecutor(context.Background(), bootstrap.client,
		operator.Public().(ed25519.PublicKey), security.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	change := roleChangeFixture(time.Now().UTC())
	change.Subject = subject
	change.ExpectedSessionVersion = 7
	change.PolicyGeneration = 1
	change.Nonce = strings.Repeat("d", 32)
	if err := editor.ApplyApprovedRoleChange(context.Background(),
		signRoleChange(t, operator, security, change)); err != nil {
		t.Fatal("first-generation signers could not perform approved role grant", err)
	}
	if role, version := roleState(t, db, subject); role != "admin" || version != 8 {
		t.Fatal("approved role transition missing after genesis")
	}
}

func TestRoleBootstrapRejectsForgeryWrongEnvironmentAndUnknownKeys(t *testing.T) {
	db, bootstrap, signed := roleBootstrapFixture(t)
	invalid := []SignedRoleBootstrap{}
	tampered := signed
	tampered.Statement.Environment = "production"
	invalid = append(invalid, tampered)
	mutated := signed
	mutated.Statement.OperatorPublicKey = strings.Repeat("f",64)
	invalid = append(invalid, mutated)
	swapped := signed
	swapped.AuthorityASignature, swapped.AuthorityBSignature = signed.AuthorityBSignature, signed.AuthorityASignature
	invalid = append(invalid, swapped)
	swappedProofs := signed
	swappedProofs.OperatorProof, swappedProofs.SecurityProof = signed.SecurityProof, signed.OperatorProof
	invalid = append(invalid, swappedProofs)
	missing := signed
	missing.SecurityProof = nil
	invalid = append(invalid, missing)
	bad := signed
	bad.AuthorityASignature = append([]byte(nil), bad.AuthorityASignature...)
	bad.AuthorityASignature[0] ^= 1
	invalid = append(invalid, bad)
	for i, candidate := range invalid {
		if err := bootstrap.Bootstrap(context.Background(), candidate); !errors.Is(err, ErrRoleBootstrapDenied) {
			t.Fatalf("invalid signature or request %d accepted: %v", i, err)
		}
	}
	authorityA, authorityB := roleBootstrapAuthorities()
	operator, security := roleKeys()
	otherOperator := roleBootstrapStatement(time.Now().UTC(), authorityA, security)
	if err := bootstrap.Bootstrap(context.Background(), signRoleBootstrap(t, otherOperator,
		authorityA, authorityB, authorityA, security)); !errors.Is(err, ErrRoleBootstrapDenied) {
		t.Fatal("governance key reused as operational signer")
	}
	if _, err := NewStagingRoleBootstrapper(context.Background(), bootstrap.client,
		authorityA.Public().(ed25519.PublicKey), authorityA.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRoleBootstrapDenied) {
		t.Fatal("same governance authority used twice")
	}
	if err := (*StagingRoleBootstrapper)(nil).Bootstrap(context.Background(), signed); !errors.Is(err, ErrRoleBootstrapDenied) {
		t.Fatal("nil bootstrapper approved role genesis")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bootstrap.Bootstrap(ctx, signed); !errors.Is(err, ErrRoleBootstrapDenied) {
		t.Fatal("cancelled request approved role genesis")
	}
	for _, tc := range []struct {
		name string
		mutate func(*RoleBootstrapStatement)
	}{
		{"wrong action", func(s *RoleBootstrapStatement) { s.Action = "bootstrap-staging-signers" }},
		{"unknown issuer", func(s *RoleBootstrapStatement) { s.ReviewIssue = "https://example.com" }},
		{"unsigned nonce", func(s *RoleBootstrapStatement) { s.Nonce = "" }},
		{"bad evidence", func(s *RoleBootstrapStatement) { s.EvidenceSHA256 = "bad" }},
		{"same keys", func(s *RoleBootstrapStatement) { s.SecurityPublicKey = s.OperatorPublicKey }},
		{"upper hex", func(s *RoleBootstrapStatement) { s.OperatorPublicKey = strings.ToUpper(s.OperatorPublicKey) }},
		{"invalid key", func(s *RoleBootstrapStatement) { s.SecurityPublicKey = "abc" }},
		{"expiry beyond 5m", func(s *RoleBootstrapStatement) { s.ExpiresAt = s.IssuedAt + 301 }},
		{"expired", func(s *RoleBootstrapStatement) { s.ExpiresAt = s.IssuedAt }},
		{"before issued", func(s *RoleBootstrapStatement) { s.NotBefore = s.IssuedAt - 1 }},
		{"oversized signer window", func(s *RoleBootstrapStatement) { s.NotAfter = s.NotBefore + int64(roleBootstrapMaxSignerLifetime.Seconds()) + 1 }},
		{"zero signer window", func(s *RoleBootstrapStatement) { s.NotAfter = s.NotBefore }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			change := signed.Statement
			tc.mutate(&change)
			if _, err := RoleBootstrapMessage(change); !errors.Is(err, ErrRoleBootstrapDenied) {
				t.Fatal("invalid role signer bootstrap accepted", err)
			}
		})
	}
	n, err := db.Collection(roleJournal).CountDocuments(context.Background(), bson.D{})
	if err != nil || n != 0 {
		t.Fatal("forged requests created audit evidence", n, err)
	}
}

func TestRoleSignerBootstrapRollbackAndDeletionCannotRebootstrap(t *testing.T) {
	db, bootstrap, signed := roleBootstrapFixture(t)
	bootstrap.afterPolicyWrite = func() error { return errors.New("synthetic rollback") }
	if err := bootstrap.Bootstrap(context.Background(), signed); !errors.Is(err, ErrRoleBootstrapStore) {
		t.Fatal("partial role bootstrap reported success", err)
	}
	for _, collection := range []string{roleJournal, rolePolicy} {
		n, err := db.Collection(collection).CountDocuments(context.Background(), bson.D{})
		if err != nil || n != 0 {
			t.Fatal("aborted role signer genesis left committed data", collection, n, err)
		}
	}
	bootstrap.afterPolicyWrite = nil
	if err := bootstrap.Bootstrap(context.Background(), signed); err != nil {
		t.Fatal("retry after rollback could not bootstrap", err)
	}
	if _, err := db.Collection(rolePolicy).DeleteOne(context.Background(), bson.D{{Key: "_id", Value: rolePolicyID}}); err != nil {
		t.Fatal(err)
	}
	authorityA, authorityB := roleBootstrapAuthorities()
	operator, security := roleKeys()
	request := roleBootstrapStatement(time.Now().UTC(), operator, security)
	request.Nonce = strings.Repeat("e", 32)
	if err := bootstrap.Bootstrap(context.Background(),
		signRoleBootstrap(t, request, authorityA, authorityB, operator, security)); !errors.Is(err, ErrRoleBootstrapConflict) {
		t.Fatal("deleted policy silently re-enrolled new signer policy", err)
	}
	n, err := db.Collection(rolePolicy).CountDocuments(context.Background(), bson.D{})
	if err != nil || n != 0 {
		t.Fatal("genesis repeat recreated deleted policy", n, err)
	}
}

func TestConcurrentRoleSignerBootstrapOneWinner(t *testing.T) {
	db, bootstrap, signed := roleBootstrapFixture(t)
	var successes atomic.Int64
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 6; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := bootstrap.Bootstrap(ctx, signed)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrRoleBootstrapConflict) && !errors.Is(err, ErrRoleBootstrapStore) {
				t.Errorf("unexpected role bootstrap conflict response: %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent role genesis had %d winners", successes.Load())
	}
	for _, collection := range []string{roleJournal, rolePolicy} {
		n, err := db.Collection(collection).CountDocuments(context.Background(), bson.D{})
		if err != nil || n != 1 {
			t.Fatal("concurrent role genesis produced incomplete or duplicate evidence", collection, n, err)
		}
	}
}
