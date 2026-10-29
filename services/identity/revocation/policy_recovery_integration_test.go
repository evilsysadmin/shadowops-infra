package revocation

import (
	"bytes"
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

func recoveryTestKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
}

func recoveryStatement(now time.Time, retired SignedRetirement, newOperator, newSecurity ed25519.PrivateKey) RecoveryStatement {
	return RecoveryStatement{
		Environment:              "staging",
		Action:                   recoveryAction,
		RevokedGeneration:        retired.Statement.Generation + 1,
		RevokedOperatorKeySHA256: retired.Statement.OperatorKeySHA256,
		RevokedSecurityKeySHA256: retired.Statement.SecurityKeySHA256,
		NewOperatorPublicKey:     hex.EncodeToString(newOperator.Public().(ed25519.PublicKey)),
		NewSecurityPublicKey:     hex.EncodeToString(newSecurity.Public().(ed25519.PublicKey)),
		NotBefore:                now.Unix(),
		NotAfter:                 now.Add(24 * time.Hour).Unix(),
		ReviewIssue:              retired.Statement.ReviewIssue,
		EvidenceSHA256:           strings.Repeat("d", 64),
		Nonce:                    strings.Repeat("b", 32),
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(5 * time.Minute).Unix(),
	}
}

func signedRecovery(t *testing.T, statement RecoveryStatement, govA, govB, newOp, newSec ed25519.PrivateKey) SignedRecovery {
	t.Helper()
	msg, err := RecoveryMessage(statement)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRecovery{
		Statement:           statement,
		AuthorityASignature: ed25519.Sign(govA, msg),
		AuthorityBSignature: ed25519.Sign(govB, msg),
		NewOperatorProof:    ed25519.Sign(newOp, msg),
		NewSecurityProof:    ed25519.Sign(newSec, msg),
	}
}

func recoveryFixture(t *testing.T) (*mongo.Database, *AuthorizedStagingRevoker, *StagingPolicyRecoverer, SignedRecovery, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	db, original, retirer, retiring := retirementFixture(t)
	if err := retirer.Retire(context.Background(), retiring); err != nil {
		t.Fatal("cannot seed audited retirement", err)
	}
	govA, govB := policyRetirementKeys()
	recoverer, err := NewStagingPolicyRecoverer(context.Background(), original.client,
		govA.Public().(ed25519.PublicKey), govB.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	newOp, newSec := recoveryTestKeys()
	statement := recoveryStatement(time.Now().UTC(), retiring, newOp, newSec)
	return db, original, recoverer, signedRecovery(t, statement, govA, govB, newOp, newSec), newOp, newSec
}

func TestRecoveryCommitsNewSignersAndAuditWithoutChangingUserSessions(t *testing.T) {
	db, oldRevoker, recoverer, signed, newOp, newSec := recoveryFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 93)
	if err := recoverer.Recover(context.Background(), signed); err != nil {
		t.Fatal("valid audited recovery denied", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "active" || generation != 3 {
		t.Fatal("revoked signer policy was not recovered", state, generation)
	}
	if retirementJournalCount(t, db) != 2 {
		t.Fatal("recovery journal missing or duplicate")
	}
	var event struct {
		RevokedGeneration    int64  `bson:"revoked_generation"`
		ActivatedGeneration  int64  `bson:"activated_generation"`
		PriorRetirementNonce string `bson:"prior_retirement_nonce"`
	}
	if err := db.Collection(retirementJournalCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: "staging:" + recoveryAction + ":" + signed.Statement.Nonce}}).Decode(&event); err != nil {
		t.Fatal("recovery event not committed", err)
	}
	if event.RevokedGeneration != 2 || event.ActivatedGeneration != 3 ||
		event.PriorRetirementNonce != strings.Repeat("a", 32) {
		t.Fatal("recovery audit did not bind predecessor retirement")
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 {
		t.Fatal("recovery unexpectedly changed user sessions or account")
	}
	oldOp, oldSec := approvalTestKeys()
	oldApproval := approvedTestCommand(t, oldOp, oldSec, syntheticSubject, 7, strings.Repeat("c", 32))
	oldApproval.Approval.PolicyGeneration = 3
	oldApproval = signedTestSuspension(t, oldApproval.Approval, oldOp, oldSec)
	if err := oldRevoker.SuspendAndRevokeApproved(context.Background(), oldApproval); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("retired cached signer accepted after recovery", err)
	}
	newRevoker, err := NewAuthorizedStagingRevoker(context.Background(), oldRevoker.client,
		newOp.Public().(ed25519.PublicKey), newSec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	fresh := approvedTestCommand(t, newOp, newSec, syntheticSubject, 7, strings.Repeat("d", 32))
	fresh.Approval.PolicyGeneration = 3
	fresh = signedTestSuspension(t, fresh.Approval, newOp, newSec)
	if err := newRevoker.SuspendAndRevokeApproved(context.Background(), fresh); err != nil {
		t.Fatal("new possession-proven signer pair denied", err)
	}
	if err := recoverer.Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatal("replayed recovery accepted", err)
	}
	if retirementJournalCount(t, db) != 2 {
		t.Fatal("replay inserted a second recovery event")
	}
}

func TestRecoveryRequiresRealCommittedRetirementEvidence(t *testing.T) {
	db, _, recoverer, signed, _, _ := recoveryFixture(t)
	_, err := db.Collection(retirementJournalCollection).DeleteMany(context.Background(), bson.D{
		{Key: "action", Value: retirementAction},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverer.Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryDenied) {
		t.Fatal("unaudited revoked policy recovered", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "revoked" || generation != 2 ||
		retirementJournalCount(t, db) != 0 {
		t.Fatal("unaudited recovery changed state or journal")
	}
}

func TestRecoveryRejectedFromActiveOrMismatchedPolicy(t *testing.T) {
	db, _, recoverer, signed, _, _ := recoveryFixture(t)
	updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
		{Key: "state", Value: "active"},
	}}})
	if err := recoverer.Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatal("already active signer policy recovered", err)
	}
	updateSyntheticPolicy(t, db, bson.D{{Key: "$set", Value: bson.D{
		{Key: "state", Value: "revoked"},
		{Key: "revoked_at", Value: time.Now().UTC().Add(-24 * time.Hour)},
	}}})
	if err := recoverer.Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatal("revocation timestamp not bound to journal", err)
	}
	if retirementJournalCount(t, db) != 1 {
		t.Fatal("rejected recovery wrote journal event")
	}
}

func TestRecoveryFailClosedOnSignaturesKeysAndWindow(t *testing.T) {
	db, _, recoverer, signed, newOp, newSec := recoveryFixture(t)
	govA, govB := policyRetirementKeys()
	variants := []SignedRecovery{}
	flippedProof := signed
	flippedProof.NewSecurityProof = append([]byte(nil), signed.NewSecurityProof...)
	flippedProof.NewSecurityProof[0] ^= 0x01
	variants = append(variants, flippedProof)
	swappedGovernance := signed
	swappedGovernance.AuthorityASignature, swappedGovernance.AuthorityBSignature =
		signed.AuthorityBSignature, signed.AuthorityASignature
	variants = append(variants, swappedGovernance)
	tampered := signed
	tampered.Statement.NewSecurityPublicKey = tampered.Statement.NewOperatorPublicKey
	variants = append(variants, tampered)
	tamperedGeneration := signed
	tamperedGeneration.Statement.RevokedGeneration++
	variants = append(variants, tamperedGeneration)
	previousOp, _ := approvalTestKeys()
	reused := signed.Statement
	reused.NewOperatorPublicKey = hex.EncodeToString(previousOp.Public().(ed25519.PublicKey))
	reusedSigned := SignedRecovery{Statement: reused}
	variants = append(variants, reusedSigned)
	for i, candidate := range variants {
		if err := recoverer.Recover(context.Background(), candidate); !errors.Is(err, ErrRecoveryDenied) {
			t.Fatalf("invalid recovery %d accepted: %v", i, err)
		}
	}
	expired := signed.Statement
	expired.IssuedAt = time.Now().UTC().Add(-10 * time.Minute).Unix()
	expired.ExpiresAt = expired.IssuedAt + 300
	expired.NotBefore = expired.IssuedAt
	expired.NotAfter = expired.IssuedAt + 86400
	if err := recoverer.Recover(context.Background(), signedRecovery(t, expired, govA, govB, newOp, newSec)); !errors.Is(err, ErrRecoveryDenied) {
		t.Fatal("expired, correctly signed recovery accepted")
	}
	for name, modify := range map[string]func(*RecoveryStatement){
		"production":   func(v *RecoveryStatement) { v.Environment = "production" },
		"wrong action": func(v *RecoveryStatement) { v.Action = retirementAction },
		"zero epoch":   func(v *RecoveryStatement) { v.RevokedGeneration = 0 },
		"bad hex":      func(v *RecoveryStatement) { v.NewOperatorPublicKey = "abcd" },
		"same key":     func(v *RecoveryStatement) { v.NewSecurityPublicKey = v.NewOperatorPublicKey },
		"old key reuse": func(v *RecoveryStatement) {
			v.NewOperatorPublicKey = hex.EncodeToString(previousOp.Public().(ed25519.PublicKey))
		},
		"early activation":   func(v *RecoveryStatement) { v.NotBefore = v.IssuedAt - 1 },
		"unbounded lifetime": func(v *RecoveryStatement) { v.NotAfter = v.NotBefore + int64(maxRecoveredSignerLifetime.Seconds()) + 1 },
		"zero window":        func(v *RecoveryStatement) { v.NotAfter = v.NotBefore },
		"unbounded approval": func(v *RecoveryStatement) { v.ExpiresAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			v := signed.Statement
			modify(&v)
			if _, err := RecoveryMessage(v); !errors.Is(err, ErrRecoveryDenied) {
				t.Fatal("invalid signed rotation statement accepted")
			}
		})
	}
	if err := (*StagingPolicyRecoverer)(nil).Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryDenied) {
		t.Fatal("nil recoverer accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recoverer.Recover(ctx, signed); !errors.Is(err, ErrRecoveryDenied) {
		t.Fatal("cancelled recovery accepted")
	}
	if state, generation := retirementPolicyState(t, db); state != "revoked" || generation != 2 ||
		retirementJournalCount(t, db) != 1 {
		t.Fatal("rejected recovery mutated policy or journal")
	}
}

func TestRecoveryTransactionRollbackAndRetry(t *testing.T) {
	db, _, recoverer, signed, _, _ := recoveryFixture(t)
	recoverer.afterPolicyWrite = func() error { return errors.New("synthetic fail after policy update") }
	if err := recoverer.Recover(context.Background(), signed); !errors.Is(err, ErrRecoveryStore) {
		t.Fatal("failed transaction did not abort", err)
	}
	if state, generation := retirementPolicyState(t, db); state != "revoked" || generation != 2 ||
		retirementJournalCount(t, db) != 1 {
		t.Fatal("aborted recovery mutated active policy or audit")
	}
	recoverer.afterPolicyWrite = nil
	if err := recoverer.Recover(context.Background(), signed); err != nil {
		t.Fatal("rolled-back approval could not be safely retried", err)
	}
}

func TestRecoveryConcurrentReplayOneWinner(t *testing.T) {
	db, _, recoverer, signed, _, _ := recoveryFixture(t)
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
			err := recoverer.Recover(ctx, signed)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrRecoveryConflict) && !errors.Is(err, ErrRecoveryStore) {
				t.Errorf("unexpected recovery race error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || retirementJournalCount(t, db) != 2 {
		t.Fatal("multiple recovery transactions committed", wins.Load())
	}
	if state, generation := retirementPolicyState(t, db); state != "active" || generation != 3 {
		t.Fatal("racing recovery left unexpected policy state")
	}
}
