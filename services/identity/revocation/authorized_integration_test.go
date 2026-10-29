package revocation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func authorizedFixture(t *testing.T) (*mongo.Database, *AuthorizedStagingRevoker, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	client, db := replica(t)
	ctx := context.Background()
	if err := db.Collection(suspensionJournalCollection).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = db.Collection(suspensionJournalCollection).Drop(c)
	})
	op, sec := approvalTestKeys()
	r, err := NewAuthorizedStagingRevoker(ctx, client,
		op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return db, r, op, sec
}

func approvedTestCommand(t *testing.T, op, sec ed25519.PrivateKey, subject string, version int64, nonce string) SignedSuspension {
	t.Helper()
	a := validTestSuspension(time.Now().UTC())
	a.Subject = subject
	a.ExpectedSessionVersion = version
	a.Nonce = nonce
	return signedTestSuspension(t, a, op, sec)
}

func journalCount(t *testing.T, db *mongo.Database) int64 {
	t.Helper()
	count, err := db.Collection(suspensionJournalCollection).CountDocuments(context.Background(), bson.D{})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestAuthorizedSuspensionCommitsAuditAndRevokesOnlySubject(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	other := "22222222-2222-4222-8222-222222222222"
	addActiveAccount(t, db, syntheticSubject, 7)
	addActiveAccount(t, db, other, 3)
	addSession(t, db, syntheticSubject, 7, 10)
	addSession(t, db, syntheticSubject, 7, 11)
	addSession(t, db, other, 3, 12)

	signed := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("a", 32))
	if err := r.SuspendAndRevokeApproved(context.Background(), signed); err != nil {
		t.Fatal("authorized suspension failed", err)
	}
	state, disabled, version := accountState(t, db, syntheticSubject)
	if state != "credential-staged-disabled" || !disabled || version != 8 ||
		sessionCount(t, db, syntheticSubject) != 0 {
		t.Fatal("account/session transaction not committed exactly", state, disabled, version)
	}
	if state, disabled, version := accountState(t, db, other); state != "active" ||
		disabled || version != 3 || sessionCount(t, db, other) != 1 {
		t.Fatal("unrelated account/session altered")
	}
	if journalCount(t, db) != 1 {
		t.Fatal("missing or duplicate durable audit event")
	}
	var event struct {
		Subject                string    `bson:"subject"`
		ExpectedSessionVersion int64     `bson:"expected_session_version"`
		Environment            string    `bson:"environment"`
		Nonce                  string    `bson:"nonce"`
		ApprovalSHA256         string    `bson:"approval_sha256"`
		OperatorKeySHA256      string    `bson:"operator_key_sha256"`
		SecurityKeySHA256      string    `bson:"security_key_sha256"`
		ExecutedAt             time.Time `bson:"executed_at"`
	}
	if err := db.Collection(suspensionJournalCollection).FindOne(context.Background(),
		bson.D{{Key: "_id", Value: "staging:suspend-and-revoke:" + signed.Approval.Nonce}}).Decode(&event); err != nil {
		t.Fatal("audit record missing", err)
	}
	if event.Subject != syntheticSubject || event.ExpectedSessionVersion != 7 ||
		event.Environment != "staging" || event.Nonce != signed.Approval.Nonce ||
		len(event.ApprovalSHA256) != 64 || len(event.OperatorKeySHA256) != 64 ||
		len(event.SecurityKeySHA256) != 64 || event.OperatorKeySHA256 == event.SecurityKeySHA256 ||
		event.ExecutedAt.IsZero() {
		t.Fatal("audit record missing nonsecret attribution fields")
	}
	if err := r.SuspendAndRevokeApproved(context.Background(), signed); !errors.Is(err, ErrConflict) {
		t.Fatal("replayed approval mutated a suspended account", err)
	}
	if journalCount(t, db) != 1 {
		t.Fatal("replay appended audit record")
	}
}

func TestAuthorizedSuspensionNonceUniqueAcrossDifferentAccounts(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	other := "22222222-2222-4222-8222-222222222222"
	addActiveAccount(t, db, syntheticSubject, 7)
	addActiveAccount(t, db, other, 9)
	addSession(t, db, other, 9, 20)
	nonce := strings.Repeat("b", 32)
	first := approvedTestCommand(t, op, sec, syntheticSubject, 7, nonce)
	second := approvedTestCommand(t, op, sec, other, 9, nonce)
	if err := r.SuspendAndRevokeApproved(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := r.SuspendAndRevokeApproved(context.Background(), second); !errors.Is(err, ErrConflict) {
		t.Fatal("reused nonce was not rejected by journal uniqueness", err)
	}
	if state, disabled, version := accountState(t, db, other); state != "active" ||
		disabled || version != 9 || sessionCount(t, db, other) != 1 {
		t.Fatal("duplicate nonce did not roll back account/session mutations")
	}
	if journalCount(t, db) != 1 {
		t.Fatal("duplicate nonce inserted additional audit evidence")
	}
}

func TestAuthorizedSuspensionRollbackAfterDeleteRestoresEverything(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 21)
	cmd := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("c", 32))
	r.afterSessionDelete = func() error { return errors.New("synthetic rollback after deletion") }
	if err := r.SuspendAndRevokeApproved(context.Background(), cmd); !errors.Is(err, ErrApprovalStore) {
		t.Fatal("expected storage failure without leaked details", err)
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 ||
		journalCount(t, db) != 0 {
		t.Fatal("aborted transaction leaked changes")
	}
	r.afterSessionDelete = nil
	if err := r.SuspendAndRevokeApproved(context.Background(), cmd); err != nil {
		t.Fatal("rollback incorrectly consumed approval nonce", err)
	}
	if journalCount(t, db) != 1 {
		t.Fatal("successful retry did not append audit")
	}
}

func TestAuthorizedSuspensionInvalidAndStaleApprovalNeverMutates(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 22)
	good := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("d", 32))
	tampered := good
	tampered.Approval.ExpectedSessionVersion = 8
	expiredApproval := good.Approval
	expiredApproval.IssuedAt = time.Now().Add(-10 * time.Minute).Unix()
	expiredApproval.ExpiresAt = expiredApproval.IssuedAt + 300
	expired := signedTestSuspension(t, expiredApproval, op, sec)
	badEnv := good.Approval
	badEnv.Environment = "production"
	badEnvSignature := good
	badEnvSignature.Approval = badEnv
	for _, cmd := range []SignedSuspension{tampered, expired, badEnvSignature} {
		if err := r.SuspendAndRevokeApproved(context.Background(), cmd); !errors.Is(err, ErrApprovalDenied) {
			t.Fatal("invalid or expired approval reached Mongo", err)
		}
	}
	if err := (*AuthorizedStagingRevoker)(nil).SuspendAndRevokeApproved(context.Background(), good); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("nil revoker accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.SuspendAndRevokeApproved(cancelled, good); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("cancelled operation accepted")
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "active" ||
		disabled || version != 7 || sessionCount(t, db, syntheticSubject) != 1 ||
		journalCount(t, db) != 0 {
		t.Fatal("invalid approval mutated account, sessions or audit")
	}
}

func TestAuthorizedSuspensionConcurrentReplaySingleWinner(t *testing.T) {
	db, r, op, sec := authorizedFixture(t)
	addActiveAccount(t, db, syntheticSubject, 7)
	addSession(t, db, syntheticSubject, 7, 23)
	cmd := approvedTestCommand(t, op, sec, syntheticSubject, 7, strings.Repeat("e", 32))
	start := make(chan struct{})
	var wins atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := r.SuspendAndRevokeApproved(ctx, cmd)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrApprovalStore) {
				t.Errorf("unexpected result for concurrent approval: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || journalCount(t, db) != 1 {
		t.Fatal("concurrent replay had multiple winners or journal entries", wins.Load())
	}
	if state, disabled, version := accountState(t, db, syntheticSubject); state != "credential-staged-disabled" ||
		!disabled || version != 8 || sessionCount(t, db, syntheticSubject) != 0 {
		t.Fatal("concurrent race left account/session changes inconsistent")
	}
}
