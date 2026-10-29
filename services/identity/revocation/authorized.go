package revocation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const suspensionJournalCollection = "admin_suspension_journal"

var ErrApprovalStore = errors.New("identity approval journal unavailable")

// AuthorizedStagingRevoker is an OFFLINE staging-only primitive. An approved
// suspension still requires independently provisioned and reviewed signing
// authorities, caller authorization and a secure operator process. Never
// expose this primitive as an HTTP endpoint without those separate gates.
type AuthorizedStagingRevoker struct {
	client   *mongo.Client
	accounts *mongo.Collection
	sessions *mongo.Collection
	journal  *mongo.Collection
	verifier *ApprovalVerifier

	afterAccountWrite  func() error // tests only: force rollback after account write
	afterSessionDelete func() error // tests only: force rollback after session deletion
}

// NewAuthorizedStagingRevoker creates the durable unique nonce index OUTSIDE
// any transaction. Neither public keys nor signatures come from Mongo or a
// request. The journal has no TTL: replay evidence must not expire with the
// short-lived approval.
func NewAuthorizedStagingRevoker(ctx context.Context, client *mongo.Client, operator, security ed25519.PublicKey) (*AuthorizedStagingRevoker, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrApprovalDenied
	}
	verifier, err := NewApprovalVerifier(operator, security)
	if err != nil {
		return nil, ErrApprovalDenied
	}
	db := client.Database(StagingDatabase)
	journal := db.Collection(suspensionJournalCollection,
		options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	_, err = journal.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "environment", Value: 1}, {Key: "action", Value: 1}, {Key: "nonce", Value: 1}},
		Options: options.Index().SetName("staging_action_nonce_unique").SetUnique(true),
	})
	if err != nil {
		return nil, ErrApprovalStore
	}
	return &AuthorizedStagingRevoker{
		client: client,
		accounts: db.Collection("pending_accounts"),
		sessions: db.Collection("sessions"),
		journal: journal,
		verifier: verifier,
	}, nil
}

// SuspendAndRevokeApproved verifies both signed roles and atomically consumes
// the nonce in an append-only audit journal, disables the exact active account,
// bumps its session_version, and removes its sessions. A duplicate nonce,
// competing suspension, invalid approval or failed journal insert commits NONE
// of those effects. Never return success before majority commit.
func (r *AuthorizedStagingRevoker) SuspendAndRevokeApproved(ctx context.Context, signed SignedSuspension) error {
	if r == nil || r.client == nil || r.accounts == nil || r.sessions == nil ||
		r.journal == nil || r.verifier == nil || ctx == nil || ctx.Err() != nil {
		return ErrApprovalDenied
	}
	if err := r.verifier.Verify(signed, time.Now().UTC()); err != nil {
		return ErrApprovalDenied
	}
	message, err := ApprovalMessage(signed.Approval)
	if err != nil {
		return ErrApprovalDenied
	}
	approvalHash := sha256.Sum256(message)
	opKeyHash := sha256.Sum256(r.verifier.operator)
	securityKeyHash := sha256.Sum256(r.verifier.security)
	a := signed.Approval

	sess, err := r.client.StartSession()
	if err != nil {
		return ErrApprovalStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())

	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		// Revalidate on every driver retry: an expired authorization must
		// not pass solely because it was valid before the first attempt.
		now := time.Now().UTC()
		if err := r.verifier.Verify(signed, now); err != nil {
			return nil, ErrApprovalDenied
		}
		filter := bson.D{
			{Key: "_id", Value: a.Subject},
			{Key: "environment", Value: "staging"},
			{Key: "state", Value: "active"},
			{Key: "credentials_disabled", Value: false},
			{Key: "session_version", Value: a.ExpectedSessionVersion},
		}
		change := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "state", Value: "credential-staged-disabled"},
				{Key: "credentials_disabled", Value: true},
			}},
			{Key: "$inc", Value: bson.D{{Key: "session_version", Value: int64(1)}}},
		}
		result, err := r.accounts.UpdateOne(tx, filter, change)
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrConflict
		}
		if r.afterAccountWrite != nil {
			if err := r.afterAccountWrite(); err != nil {
				return nil, err
			}
		}
		_, err = r.sessions.DeleteMany(tx, bson.D{
			{Key: "environment", Value: "staging"},
			{Key: "subject", Value: a.Subject},
		})
		if err != nil {
			return nil, err
		}
		if r.afterSessionDelete != nil {
			if err := r.afterSessionDelete(); err != nil {
				return nil, err
			}
		}
		// No raw signatures, passwords or private evidence are persisted.
		// Unique _id and unique (environment,action,nonce) prevent replay,
		// including a reused nonce on a DIFFERENT account.
		_, err = r.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: "staging:" + SuspendAndRevokeAction + ":" + a.Nonce},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: SuspendAndRevokeAction},
			{Key: "nonce", Value: a.Nonce},
			{Key: "subject", Value: a.Subject},
			{Key: "expected_session_version", Value: a.ExpectedSessionVersion},
			{Key: "review_issue", Value: a.ReviewIssue},
			{Key: "evidence_sha256", Value: a.EvidenceSHA256},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalHash[:])},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(opKeyHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityKeyHash[:])},
			{Key: "approved_at", Value: time.Unix(a.IssuedAt, 0).UTC()},
			{Key: "executed_at", Value: now},
		})
		if err != nil {
			return nil, err
		}
		return nil, nil
	}, txn)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConflict) || mongo.IsDuplicateKeyError(err) {
		return ErrConflict
	}
	if errors.Is(err, ErrApprovalDenied) {
		return ErrApprovalDenied
	}
	return ErrApprovalStore
}
