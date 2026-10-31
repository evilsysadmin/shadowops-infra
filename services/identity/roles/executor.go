package roles

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	roleDatabase     = "shadowops_identity_staging"
	roleJournal      = "admin_role_change_journal"
	rolePolicy       = "admin_signer_policy"
	rolePolicyID     = "staging:set-role"
	roleJournalIndex = "staging_role_nonce_unique"
)

var (
	ErrRoleStore    = errors.New("staging role transaction or audit unavailable")
	ErrRoleConflict = errors.New("staging role change conflict")
)

// StagingRoleExecutor is an OFFLINE, operator-only staging primitive. No
// public Identity service constructs this type, and its Mongo credentials
// must not be the public service's credentials. Its constructor refuses
// unprovisioned or expiring audit indexes; it does not create any DDL.
type StagingRoleExecutor struct {
	client             *mongo.Client
	accounts           *mongo.Collection
	sessions           *mongo.Collection
	tokens             *mongo.Collection
	journal            *mongo.Collection
	policy             *mongo.Collection
	verifier           *ApprovalVerifier
	afterAccountWrite  func() error // test-only fault injection
	afterSessionDelete func() error // test-only fault injection
}

func roleJournalKeys() bson.D {
	return bson.D{{Key: "environment", Value: int32(1)}, {Key: "action", Value: int32(1)}, {Key: "nonce", Value: int32(1)}}
}

// Role journal DDL must be performed separately by the schema maintainer
// with a non-TTL unique index named staging_role_nonce_unique on
// {environment:1,action:1,nonce:1}. A normal account runtime cannot repair it.
func verifyRoleJournal(ctx context.Context, journal *mongo.Collection) error {
	if ctx == nil || ctx.Err() != nil || journal == nil {
		return ErrRoleStore
	}
	cursor, err := journal.Indexes().List(ctx)
	if err != nil {
		return ErrRoleStore
	}
	var indexes []struct {
		Name    string   `bson:"name"`
		Key     bson.D   `bson:"key"`
		Unique  bool     `bson:"unique"`
		Sparse  bool     `bson:"sparse"`
		Partial bson.Raw `bson:"partialFilterExpression"`
		TTL     *int64   `bson:"expireAfterSeconds"`
	}
	if err := cursor.All(ctx, &indexes); err != nil {
		return ErrRoleStore
	}
	found := false
	for _, index := range indexes {
		if index.TTL != nil {
			return ErrRoleStore
		}
		if index.Name == roleJournalIndex {
			if !index.Unique || index.Sparse || len(index.Partial) != 0 || !reflect.DeepEqual(index.Key, roleJournalKeys()) {
				return ErrRoleStore
			}
			found = true
		}
	}
	if !found {
		return ErrRoleStore
	}
	return nil
}

func NewStagingRoleExecutor(ctx context.Context, client *mongo.Client, operator, security ed25519.PublicKey) (*StagingRoleExecutor, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrRoleApprovalDenied
	}
	verifier, err := NewApprovalVerifier(operator, security)
	if err != nil {
		return nil, err
	}
	db := client.Database(roleDatabase)
	journal := db.Collection(roleJournal, options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	if err := verifyRoleJournal(ctx, journal); err != nil {
		return nil, err
	}
	return &StagingRoleExecutor{
		client: client, accounts: db.Collection("pending_accounts"),
		sessions: db.Collection("sessions"), tokens: db.Collection("staging_cka_tokens"),
		journal: journal, policy: db.Collection(rolePolicy), verifier: verifier,
	}, nil
}

// ApplyApprovedRoleChange is a single majority Mongo transaction: revalidate
// both signatures, fence the ACTIVE signer policy, CAS the exact active
// account's old role + session version, revoke its sessions/app tokens and
// append a permanent nonce-unique audit event. Failure rolls back ALL effects.
func (r *StagingRoleExecutor) ApplyApprovedRoleChange(ctx context.Context, signed SignedRoleChange) error {
	if r == nil || r.client == nil || r.accounts == nil || r.sessions == nil ||
		r.tokens == nil || r.journal == nil || r.policy == nil || r.verifier == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrRoleApprovalDenied
	}
	if err := r.verifier.Verify(signed, time.Now().UTC()); err != nil {
		return ErrRoleApprovalDenied
	}
	message, err := ApprovalMessage(signed.Change)
	if err != nil {
		return ErrRoleApprovalDenied
	}
	a := signed.Change
	approvalHash := sha256.Sum256(message)
	operatorHash := sha256.Sum256(r.verifier.operator)
	securityHash := sha256.Sum256(r.verifier.security)
	sess, err := r.client.StartSession()
	if err != nil {
		return ErrRoleStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetReadPreference(readpref.Primary()).SetWriteConcern(writeconcern.Majority())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		now := time.Now().UTC()
		if err := r.verifier.Verify(signed, now); err != nil {
			return nil, ErrRoleApprovalDenied
		}
		signedAt := time.Unix(a.IssuedAt, 0).UTC()
		cutoff := signedAt
		if now.Before(cutoff) {
			cutoff = now
		}
		expiresAfter := signedAt
		if now.After(expiresAfter) {
			expiresAfter = now
		}
		policyFilter := bson.D{
			{Key: "_id", Value: rolePolicyID}, {Key: "environment", Value: "staging"},
			{Key: "action", Value: SetRoleAction}, {Key: "state", Value: "active"},
			{Key: "generation", Value: a.PolicyGeneration},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(operatorHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityHash[:])},
			{Key: "not_before", Value: bson.D{{Key: "$lte", Value: cutoff}}},
			{Key: "not_after", Value: bson.D{{Key: "$gt", Value: expiresAfter}}},
		}
		policyWrite, err := r.policy.UpdateOne(tx, policyFilter, bson.D{{Key: "$inc", Value: bson.D{{Key: "use_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if policyWrite.ModifiedCount != 1 {
			return nil, ErrRoleApprovalDenied
		}

		filter := bson.D{
			{Key: "_id", Value: a.Subject}, {Key: "environment", Value: "staging"},
			{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false},
			{Key: "session_version", Value: a.ExpectedSessionVersion},
		}
		if a.From == User {
			// Legacy records with no role are USER; explicit null/unknown
			// values must never be treated as a valid role.
			filter = append(filter, bson.E{Key: "$or", Value: bson.A{
				bson.D{{Key: "role", Value: string(User)}},
				bson.D{{Key: "role", Value: bson.D{{Key: "$exists", Value: false}}}},
			}})
		} else {
			filter = append(filter, bson.E{Key: "role", Value: string(Admin)})
		}
		result, err := r.accounts.UpdateOne(tx, filter, bson.D{
			{Key: "$set", Value: bson.D{{Key: "role", Value: string(a.To)}}},
			{Key: "$inc", Value: bson.D{{Key: "session_version", Value: int64(1)}}},
		})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrRoleConflict
		}
		if r.afterAccountWrite != nil {
			if err := r.afterAccountWrite(); err != nil {
				return nil, err
			}
		}
		if _, err := r.sessions.DeleteMany(tx, bson.D{
			{Key: "environment", Value: "staging"}, {Key: "subject", Value: a.Subject},
		}); err != nil {
			return nil, err
		}
		if r.afterSessionDelete != nil {
			if err := r.afterSessionDelete(); err != nil {
				return nil, err
			}
		}
		if _, err := r.tokens.UpdateMany(tx, bson.D{
			{Key: "subject", Value: a.Subject}, {Key: "active", Value: true},
		}, bson.D{{Key: "$set", Value: bson.D{{Key: "active", Value: false}}}}); err != nil {
			return nil, err
		}
		_, err = r.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: "staging:set-role:" + a.Nonce},
			{Key: "environment", Value: "staging"}, {Key: "action", Value: SetRoleAction},
			{Key: "nonce", Value: a.Nonce}, {Key: "subject", Value: a.Subject},
			{Key: "from", Value: string(a.From)}, {Key: "to", Value: string(a.To)},
			{Key: "expected_session_version", Value: a.ExpectedSessionVersion},
			{Key: "policy_generation", Value: a.PolicyGeneration},
			{Key: "review_issue", Value: a.ReviewIssue},
			{Key: "evidence_sha256", Value: a.EvidenceSHA256},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalHash[:])},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(operatorHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityHash[:])},
			{Key: "approved_at", Value: signedAt}, {Key: "executed_at", Value: now},
		})
		return nil, err
	}, txn)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRoleConflict) || mongo.IsDuplicateKeyError(err) {
		return ErrRoleConflict
	}
	if errors.Is(err, ErrRoleApprovalDenied) {
		return ErrRoleApprovalDenied
	}
	return ErrRoleStore
}
