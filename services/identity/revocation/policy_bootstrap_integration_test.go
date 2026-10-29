package revocation

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

func bootstrapTestKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return approvalTestKeys()
}

func validBootstrap(now time.Time, op, sec ed25519.PrivateKey) BootstrapStatement {
	return BootstrapStatement{
		Environment:          "staging",
		Action:               bootstrapAction,
		NewOperatorPublicKey: hex.EncodeToString(op.Public().(ed25519.PublicKey)),
		NewSecurityPublicKey: hex.EncodeToString(sec.Public().(ed25519.PublicKey)),
		NotBefore:            now.Unix(),
		NotAfter:             now.Add(24 * time.Hour).Unix(),
		ReviewIssue:          "https://github.com/evilsysadmin/shadowops-infra/issues/287",
		EvidenceSHA256:       strings.Repeat("a", 64),
		Nonce:                strings.Repeat("b", 32),
		IssuedAt:             now.Unix(),
		ExpiresAt:            now.Add(5 * time.Minute).Unix(),
	}
}

func signedBootstrap(t *testing.T, v BootstrapStatement, govA, govB, op, sec ed25519.PrivateKey) SignedBootstrap {
	t.Helper()
	msg, err := BootstrapMessage(v)
	if err != nil {
		t.Fatal(err)
	}
	return SignedBootstrap{
		Statement:           v,
		AuthorityASignature: ed25519.Sign(govA, msg),
		AuthorityBSignature: ed25519.Sign(govB, msg),
		NewOperatorProof:    ed25519.Sign(op, msg),
		NewSecurityProof:    ed25519.Sign(sec, msg),
	}
}

func bootstrapFixture(t *testing.T) (*mongo.Database, *StagingSignerBootstrapper, SignedBootstrap) {
	t.Helper()
	client, db := replica(t)
	ctx := context.Background()
	for _, collection := range []string{signerPolicyCollection, retirementJournalCollection} {
		if err := db.Collection(collection).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, collection := range []string{signerPolicyCollection, retirementJournalCollection} {
			_ = db.Collection(collection).Drop(ctx)
		}
	})
	govA, govB := policyRetirementKeys()
	b, err := NewStagingSignerBootstrapper(ctx, client,
		govA.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	op, sec := bootstrapTestKeys()
	cmd := signedBootstrap(t, validBootstrap(time.Now().UTC(), op, sec), govA, govB, op, sec)
	return db, b, cmd
}

func TestFirstBootstrapEnablesOnlyPinnedStagingSignerAndCreatesOneGenesis(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 90)
	if err := b.Bootstrap(context.Background(), signed); err != nil {
		t.Fatal("valid one-time bootstrap failed", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "active" || generation != 1 {
		t.Fatal("initial policy missing", state, generation)
	}
	if retirementJournalCount(t, db) != 1 {
		t.Fatal("missing or duplicate genesis event")
	}
	var audit struct {
		Action            string `bson:"action"`
		Generation        int64  `bson:"generation"`
		OperatorKeySHA256 string `bson:"operator_key_sha256"`
		SecurityKeySHA256 string `bson:"security_key_sha256"`
	}
	if err := db.Collection(retirementJournalCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: bootstrapEventID}}).Decode(&audit); err != nil {
		t.Fatal("genesis audit event not recorded", err)
	}
	if audit.Action != bootstrapAction || audit.Generation != 1 ||
		len(audit.OperatorKeySHA256) != 64 || len(audit.SecurityKeySHA256) != 64 ||
		audit.OperatorKeySHA256 == audit.SecurityKeySHA256 {
		t.Fatal("incomplete signer genesis evidence")
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 {
		t.Fatal("bootstrap must not touch user accounts or sessions")
	}
	if err := b.Bootstrap(context.Background(), signed); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatal("replayed genesis was accepted", err)
	}
	govA, govB := policyRetirementKeys()
	op, sec := bootstrapTestKeys()
	fresh := validBootstrap(time.Now().UTC(), op, sec)
	fresh.Nonce = strings.Repeat("c", 32)
	if err := b.Bootstrap(context.Background(), signedBootstrap(t, fresh, govA, govB, op, sec)); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatal("new approval could create a second initial policy", err)
	}
	if retirementJournalCount(t, db) != 1 {
		t.Fatal("replay produced an extra genesis event")
	}
	suspender, err := NewAuthorizedStagingRevoker(context.Background(), b.governance.client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	suspend := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("e", 32))
	if err := suspender.SuspendAndRevokeApproved(context.Background(), suspend); err != nil {
		t.Fatal("legitimate initial-generation signer could not suspend", err)
	}
}

func TestDeletingPolicyCannotRepeatSignedBootstrapWhileAuditSurvives(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	if err := b.Bootstrap(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	_, err := db.Collection(signerPolicyCollection).DeleteOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}})
	if err != nil {
		t.Fatal(err)
	}
	govA, govB := policyRetirementKeys()
	op, sec := bootstrapTestKeys()
	retry := validBootstrap(time.Now().UTC(), op, sec)
	retry.Nonce = strings.Repeat("d", 32)
	if err := b.Bootstrap(context.Background(), signedBootstrap(t, retry, govA, govB, op, sec)); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatal("deleting policy permitted destructive rebootstrap", err)
	}
	if retirementJournalCount(t, db) != 1 {
		t.Fatal("genesis audit was altered on rejected rebootstrap")
	}
	if count, err := db.Collection(signerPolicyCollection).CountDocuments(context.Background(), bson.D{}); err != nil || count != 0 {
		t.Fatal("rejected rebootstrap recreated missing policy", err)
	}
}

func TestBootstrapRefusesExistingUntrackedPolicy(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	_, err := db.Collection(signerPolicyCollection).InsertOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}, {Key: "environment", Value: "staging"},
			{Key: "action", Value: SuspendAndRevokeAction}, {Key: "state", Value: "revoked"},
			{Key: "generation", Value: int64(8)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Bootstrap(context.Background(), signed); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatal("existing revoked/malformed policy was overwritten", err)
	}
	if retirementJournalCount(t, db) != 0 {
		t.Fatal("rejected bootstrap emitted genesis evidence")
	}
}

func TestBootstrapRejectsMissingAndForgedFourSignatures(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	invalid := []SignedBootstrap{}
	tampered := signed
	tampered.Statement.Nonce = strings.Repeat("c", 32)
	invalid = append(invalid, tampered)
	swapped := signed
	swapped.AuthorityASignature, swapped.AuthorityBSignature = signed.AuthorityBSignature, signed.AuthorityASignature
	invalid = append(invalid, swapped)
	missingProof := signed
	missingProof.NewSecurityProof = nil
	invalid = append(invalid, missingProof)
	wrongProof := signed
	wrongProof.NewOperatorProof = append([]byte(nil), signed.NewOperatorProof...)
	wrongProof.NewOperatorProof[0] ^= 1
	invalid = append(invalid, wrongProof)
	for i, v := range invalid {
		if err := b.Bootstrap(context.Background(), v); !errors.Is(err, ErrBootstrapDenied) {
			t.Fatalf("invalid bootstrap %d was accepted: %v", i, err)
		}
	}
	govA, govB := policyRetirementKeys()
	op, sec := bootstrapTestKeys()
	invalidAuthority, err := NewStagingSignerBootstrapper(context.Background(), b.governance.client,
		op.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	reSigned := signedBootstrap(t, signed.Statement, op, govB, op, sec)
	if err := invalidAuthority.Bootstrap(context.Background(), reSigned); !errors.Is(err, ErrBootstrapDenied) {
		t.Fatal("operational signer was also accepted as governance authority", err)
	}
	if _, err := NewStagingSignerBootstrapper(context.Background(), b.governance.client,
		govA.Public().(ed25519.PublicKey), govA.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("same governance signer enrolled twice")
	}
	for name, alter := range map[string]func(*BootstrapStatement){
		"production":          func(v *BootstrapStatement) { v.Environment = "production" },
		"wrong action":        func(v *BootstrapStatement) { v.Action = retirementAction },
		"bad key":             func(v *BootstrapStatement) { v.NewSecurityPublicKey = "invalid" },
		"same new key":        func(v *BootstrapStatement) { v.NewSecurityPublicKey = v.NewOperatorPublicKey },
		"not before approval": func(v *BootstrapStatement) { v.NotBefore = v.IssuedAt - 1 },
		"too long operating window": func(v *BootstrapStatement) {
			v.NotAfter = v.NotBefore + int64(maxRecoveredSignerLifetime.Seconds()) + 1
		},
		"expired":        func(v *BootstrapStatement) { v.ExpiresAt = v.IssuedAt },
		"unsigned nonce": func(v *BootstrapStatement) { v.Nonce = "" },
		"foreign ticket": func(v *BootstrapStatement) { v.ReviewIssue = "https://example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			request := signed.Statement
			alter(&request)
			if _, err := BootstrapMessage(request); !errors.Is(err, ErrBootstrapDenied) {
				t.Fatal("invalid genesis statement accepted")
			}
		})
	}
	if err := (*StagingSignerBootstrapper)(nil).Bootstrap(context.Background(), signed); !errors.Is(err, ErrBootstrapDenied) {
		t.Fatal("nil bootstrapper accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Bootstrap(ctx, signed); !errors.Is(err, ErrBootstrapDenied) {
		t.Fatal("cancelled bootstrap accepted")
	}
	if retirementJournalCount(t, db) != 0 {
		t.Fatal("invalid statements appended audit evidence")
	}
}

func TestBootstrapRollbackIsAtomicAndApprovalCanRetry(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	b.afterPolicyWrite = func() error { return errors.New("inject failure after genesis and policy insert") }
	if err := b.Bootstrap(context.Background(), signed); !errors.Is(err, ErrBootstrapStore) {
		t.Fatal("bootstrap failure did not abort", err)
	}
	if count, err := db.Collection(signerPolicyCollection).CountDocuments(context.Background(), bson.D{}); err != nil || count != 0 ||
		retirementJournalCount(t, db) != 0 {
		t.Fatal("abort left policy or genesis event behind")
	}
	b.afterPolicyWrite = nil
	if err := b.Bootstrap(context.Background(), signed); err != nil {
		t.Fatal("transaction rollback consumed genesis nonce", err)
	}
}

func TestBootstrapConcurrentRequestsExactlyOneWinner(t *testing.T) {
	db, b, signed := bootstrapFixture(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := b.Bootstrap(ctx, signed)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrBootstrapConflict) && !errors.Is(err, ErrBootstrapStore) {
				t.Errorf("unexpected concurrent genesis error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || retirementJournalCount(t, db) != 1 {
		t.Fatal("concurrent bootstraps produced multiple policies or missing journal", wins.Load())
	}
	if state, generation := retirementPolicyState(t, db); state != "active" || generation != 1 {
		t.Fatal("race left incorrect initial signer policy")
	}
}
