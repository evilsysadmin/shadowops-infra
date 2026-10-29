package revocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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

func policyRetirementKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
}

func retirementStatement(now time.Time, operator, security ed25519.PrivateKey) RetirementStatement {
	opHash := sha256.Sum256(operator.Public().(ed25519.PublicKey))
	secHash := sha256.Sum256(security.Public().(ed25519.PublicKey))
	return RetirementStatement{
		Environment: "staging",
		Action: retirementAction,
		Generation: 1,
		OperatorKeySHA256: hex.EncodeToString(opHash[:]),
		SecurityKeySHA256: hex.EncodeToString(secHash[:]),
		ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287",
		EvidenceSHA256: strings.Repeat("c", 64),
		Nonce: strings.Repeat("a", 32),
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func signRetirement(t *testing.T, v RetirementStatement, a, b ed25519.PrivateKey) SignedRetirement {
	t.Helper()
	message, err := RetirementMessage(v)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRetirement{
		Statement: v,
		AuthorityASignature: ed25519.Sign(a, message),
		AuthorityBSignature: ed25519.Sign(b, message),
	}
}

func retirementFixture(t *testing.T) (*mongo.Database, *AuthorizedStagingRevoker, *StagingPolicyRetirer, SignedRetirement) {
	t.Helper()
	db, existing, op, sec := authorizedFixture(t)
	ctx := context.Background()
	if err := db.Collection(retirementJournalCollection).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = db.Collection(retirementJournalCollection).Drop(ctx)
	})
	a, b := policyRetirementKeys()
	retirer, err := NewStagingPolicyRetirer(ctx, existing.client,
		a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	signed := signRetirement(t, retirementStatement(time.Now().UTC(), op, sec), a, b)
	return db, existing, retirer, signed
}

func retirementJournalCount(t *testing.T, db *mongo.Database) int64 {
	t.Helper()
	count, err := db.Collection(retirementJournalCollection).CountDocuments(context.Background(), bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func retirementPolicyState(t *testing.T, db *mongo.Database) (string, int64) {
	t.Helper()
	var doc struct {
		State string `bson:"state"`
		Generation int64 `bson:"generation"`
	}
	if err := db.Collection(signerPolicyCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: signerPolicyID}}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.State, doc.Generation
}

func TestPolicyRetirementCommitRevokesSignerWithoutTouchingAccounts(t *testing.T) {
	db, suspender, retirer, signed := retirementFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 80)
	if err := retirer.Retire(context.Background(), signed); err != nil {
		t.Fatal("valid retirement failed", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "revoked" || generation != 2 {
		t.Fatal("signer policy was not retired", state, generation)
	}
	if got := retirementJournalCount(t, db); got != 1 {
		t.Fatal("retirement audit journal not durable", got)
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 {
		t.Fatal("retiring admin signers unexpectedly changed user sessions/accounts")
	}
	// An otherwise valid signed suspension is denied after retirement.
	op, sec := approvalTestKeys()
	valid := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("f", 32))
	if err := suspender.SuspendAndRevokeApproved(context.Background(), valid); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("stale signer remained authorized after emergency retirement", err)
	}
	if err := retirer.Retire(context.Background(), signed); !errors.Is(err, ErrRetirementConflict) {
		t.Fatal("replayed emergency retirement accepted", err)
	}
}

func TestPolicyRetirementRejectsWrongSignersAndCriticalFields(t *testing.T) {
	db, _, retirer, valid := retirementFixture(t)
	if err := (*StagingPolicyRetirer)(nil).Retire(context.Background(), valid); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("nil retirer accepted")
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retirer.Retire(c, valid); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("cancelled retirement accepted")
	}
	a, b := policyRetirementKeys()
	if _, err := NewStagingPolicyRetirer(context.Background(), retirer.client,
		a.Public().(ed25519.PublicKey), a.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("same governance authority used twice")
	}
	if _, err := NewStagingPolicyRetirer(context.Background(), nil,
		a.Public().(ed25519.PublicKey), b.Public().(ed25519.PublicKey)); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("missing Mongo client accepted")
	}
	tampered := valid
	tampered.Statement.Generation = 2
	if err := retirer.Retire(context.Background(), tampered); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("tampered policy generation accepted")
	}
	swapped := valid
	swapped.AuthorityASignature, swapped.AuthorityBSignature = valid.AuthorityBSignature, valid.AuthorityASignature
	if err := retirer.Retire(context.Background(), swapped); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("governance roles could be swapped")
	}
	expired := valid.Statement
	expired.IssuedAt = time.Now().Add(-15*time.Minute).Unix()
	expired.ExpiresAt = expired.IssuedAt + 300
	if err := retirer.Retire(context.Background(), signRetirement(t, expired, a, b)); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("expired valid signatures accepted")
	}
	cases := map[string]func(*RetirementStatement){
		"production": func(s *RetirementStatement) { s.Environment = "production" },
		"wrong action": func(s *RetirementStatement) { s.Action = "activate" },
		"zero generation": func(s *RetirementStatement) { s.Generation = 0 },
		"bad operator": func(s *RetirementStatement) { s.OperatorKeySHA256 = "invalid" },
		"same roles": func(s *RetirementStatement) { s.SecurityKeySHA256 = s.OperatorKeySHA256 },
		"bad ticket": func(s *RetirementStatement) { s.ReviewIssue = "https://example.com/" },
		"bad nonce": func(s *RetirementStatement) { s.Nonce = "" },
		"bad evidence": func(s *RetirementStatement) { s.EvidenceSHA256 = "" },
		"long expiry": func(s *RetirementStatement) { s.ExpiresAt++ },
	}
	for label, change := range cases {
		t.Run(label, func(t *testing.T) {
			v := valid.Statement
			change(&v)
			if _, err := RetirementMessage(v); !errors.Is(err, ErrRetirementDenied) {
				t.Fatal("invalid command could be signed")
			}
		})
	}
	// A governance authority must be independent from the operational keys.
	op, sec := approvalTestKeys()
	invalidAuthority, err := NewStagingPolicyRetirer(context.Background(), retirer.client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	wronglySigned := signRetirement(t, valid.Statement, op, sec)
	if err := invalidAuthority.Retire(context.Background(), wronglySigned); !errors.Is(err, ErrRetirementDenied) {
		t.Fatal("operational keys could also serve as emergency governance keys")
	}
	if state, generation := retirementPolicyState(t, db); state != "active" || generation != 1 ||
		retirementJournalCount(t, db) != 0 {
		t.Fatal("invalid approval mutated signer policy or audit")
	}
}

func TestPolicyRetirementRollbackPreservesActivePolicyAndNonce(t *testing.T) {
	db, _, retirer, signed := retirementFixture(t)
	retirer.afterPolicyWrite = func() error { return errors.New("forced journal rollback") }
	if err := retirer.Retire(context.Background(), signed); !errors.Is(err, ErrRetirementStore) {
		t.Fatal("synthetic failed transaction did not abort", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "active" ||
		generation != 1 || retirementJournalCount(t, db) != 0 {
		t.Fatal("failed transaction leaked policy update or nonce")
	}
	retirer.afterPolicyWrite = nil
	if err := retirer.Retire(context.Background(), signed); err != nil {
		t.Fatal("same approval was consumed by rolled back transaction", err)
	}
}

func TestPolicyRetirementConcurrentReplaySingleWinner(t *testing.T) {
	db, _, retirer, signed := retirementFixture(t)
	var wins atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := retirer.Retire(ctx, signed)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrRetirementConflict) &&
				!errors.Is(err, ErrRetirementStore) {
				t.Errorf("unexpected concurrent retirement result: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || retirementJournalCount(t, db) != 1 {
		t.Fatal("concurrent retirements committed more than one command", wins.Load())
	}
	if state, generation := retirementPolicyState(t, db); state != "revoked" || generation != 2 {
		t.Fatal("concurrent retirement final policy is inconsistent")
	}
}
