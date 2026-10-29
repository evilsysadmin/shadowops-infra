package revocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	retirementAction            = "retire-signer-policy"
	retirementDomain            = "shadowops-identity-policy-retirement-v1\n"
	retirementJournalCollection = "admin_signer_policy_events"
)

var (
	ErrRetirementDenied   = errors.New("identity offline signer policy retirement denied")
	ErrRetirementConflict = errors.New("identity signer policy retirement conflict")
	ErrRetirementStore    = errors.New("identity signer policy retirement unavailable")
)

// RetirementStatement identifies only the CURRENT staging signer policy and
// its exact generation/key fingerprints. A future generation or rotated key
// cannot be retired with an old signature. Both reviewing authorities must
// separately inspect out-of-band evidence; an issue URL proves nothing.
type RetirementStatement struct {
	Environment       string `json:"environment"`
	Action            string `json:"action"`
	Generation        int64  `json:"generation"`
	OperatorKeySHA256 string `json:"operator_key_sha256"`
	SecurityKeySHA256 string `json:"security_key_sha256"`
	ReviewIssue       string `json:"review_issue"`
	EvidenceSHA256    string `json:"evidence_sha256"`
	Nonce             string `json:"nonce"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
}

type SignedRetirement struct {
	Statement           RetirementStatement
	AuthorityASignature []byte
	AuthorityBSignature []byte
}

// RetirementMessage fixes encoding, order and domain separation. No flexible
// action, environment or alternative policy ID is permitted.
func RetirementMessage(v RetirementStatement) ([]byte, error) {
	if v.Environment != "staging" || v.Action != retirementAction ||
		v.Generation <= 0 || v.Generation == math.MaxInt64 ||
		!approvalSHA256.MatchString(v.OperatorKeySHA256) ||
		!approvalSHA256.MatchString(v.SecurityKeySHA256) ||
		v.OperatorKeySHA256 == v.SecurityKeySHA256 ||
		!approvalIssue.MatchString(v.ReviewIssue) ||
		!approvalSHA256.MatchString(v.EvidenceSHA256) ||
		!approvalNonce.MatchString(v.Nonce) ||
		v.IssuedAt < 1577836800 || v.ExpiresAt > 4102444800 ||
		v.ExpiresAt <= v.IssuedAt ||
		v.ExpiresAt-v.IssuedAt > int64(approvalLifetime.Seconds()) {
		return nil, ErrRetirementDenied
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, ErrRetirementDenied
	}
	message := make([]byte, 0, len(retirementDomain)+len(payload))
	message = append(message, retirementDomain...)
	message = append(message, payload...)
	return message, nil
}

// StagingPolicyRetirer is an offline-only, separately authorized emergency
// kill switch. Governance keys must be independently enrolled and pinned by a
// trusted operator. It never provisions them or handles actual user accounts.
type StagingPolicyRetirer struct {
	client     *mongo.Client
	policy     *mongo.Collection
	journal    *mongo.Collection
	authorityA ed25519.PublicKey
	authorityB ed25519.PublicKey

	afterPolicyWrite func() error // synthetic rollback injection only
}

// NewStagingPolicyRetirer ensures the permanent unique journal index exists
// BEFORE any transaction; no TTL or broad database selection is supported.
func NewStagingPolicyRetirer(ctx context.Context, client *mongo.Client, a, b ed25519.PublicKey) (*StagingPolicyRetirer, error) {
	if ctx == nil || ctx.Err() != nil || client == nil ||
		len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize ||
		bytes.Equal(a, b) {
		return nil, ErrRetirementDenied
	}
	db := client.Database(StagingDatabase)
	journal := db.Collection(retirementJournalCollection,
		options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	_, err := journal.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "environment", Value: 1}, {Key: "action", Value: 1}, {Key: "nonce", Value: 1}},
		Options: options.Index().SetName("policy_retirement_nonce_unique").SetUnique(true),
	})
	if err != nil {
		return nil, ErrRetirementStore
	}
	return &StagingPolicyRetirer{
		client:     client,
		policy:     db.Collection(signerPolicyCollection),
		journal:    journal,
		authorityA: append(ed25519.PublicKey(nil), a...),
		authorityB: append(ed25519.PublicKey(nil), b...),
	}, nil
}

func (r *StagingPolicyRetirer) verify(s SignedRetirement, now time.Time) error {
	if r == nil || len(r.authorityA) != ed25519.PublicKeySize ||
		len(r.authorityB) != ed25519.PublicKeySize ||
		bytes.Equal(r.authorityA, r.authorityB) || now.IsZero() ||
		len(s.AuthorityASignature) != ed25519.SignatureSize ||
		len(s.AuthorityBSignature) != ed25519.SignatureSize {
		return ErrRetirementDenied
	}
	message, err := RetirementMessage(s.Statement)
	if err != nil {
		return err
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < s.Statement.IssuedAt-int64(approvalClockSkew.Seconds()) ||
		nowUnix >= s.Statement.ExpiresAt {
		return ErrRetirementDenied
	}
	hA := sha256.Sum256(r.authorityA)
	hB := sha256.Sum256(r.authorityB)
	for _, fingerprint := range []string{hex.EncodeToString(hA[:]), hex.EncodeToString(hB[:])} {
		if fingerprint == s.Statement.OperatorKeySHA256 ||
			fingerprint == s.Statement.SecurityKeySHA256 {
			return ErrRetirementDenied
		}
	}
	if !ed25519.Verify(r.authorityA, message, s.AuthorityASignature) ||
		!ed25519.Verify(r.authorityB, message, s.AuthorityBSignature) {
		return ErrRetirementDenied
	}
	return nil
}

// Retire revokes exactly one live staging signer-policy generation and writes
// its durable, single-use evidence record IN THE SAME majority transaction.
// The policy-document write conflicts with in-flight authorized suspensions
// that use its use_fence; after this commits, they cannot commit using these
// keys. No enrollment, rotation, reactivation, HTTP or production path exists.
func (r *StagingPolicyRetirer) Retire(ctx context.Context, signed SignedRetirement) error {
	if r == nil || r.client == nil || r.policy == nil || r.journal == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrRetirementDenied
	}
	if err := r.verify(signed, time.Now().UTC()); err != nil {
		return ErrRetirementDenied
	}
	statement := signed.Statement
	message, err := RetirementMessage(statement)
	if err != nil {
		return ErrRetirementDenied
	}
	approvalDigest := sha256.Sum256(message)
	aHash := sha256.Sum256(r.authorityA)
	bHash := sha256.Sum256(r.authorityB)
	sess, err := r.client.StartSession()
	if err != nil {
		return ErrRetirementStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		now := time.Now().UTC()
		if err := r.verify(signed, now); err != nil {
			return nil, ErrRetirementDenied
		}
		filter := bson.D{
			{Key: "_id", Value: signerPolicyID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: SuspendAndRevokeAction},
			{Key: "state", Value: "active"},
			{Key: "generation", Value: statement.Generation},
			{Key: "operator_key_sha256", Value: statement.OperatorKeySHA256},
			{Key: "security_key_sha256", Value: statement.SecurityKeySHA256},
		}
		result, err := r.policy.UpdateOne(tx, filter, bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "state", Value: "revoked"},
				{Key: "revoked_at", Value: now},
			}},
			{Key: "$inc", Value: bson.D{{Key: "generation", Value: int64(1)}}},
		})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrRetirementConflict
		}
		if r.afterPolicyWrite != nil {
			if err := r.afterPolicyWrite(); err != nil {
				return nil, err
			}
		}
		_, err = r.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: "staging:" + retirementAction + ":" + statement.Nonce},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: retirementAction},
			{Key: "nonce", Value: statement.Nonce},
			{Key: "generation", Value: statement.Generation},
			{Key: "operator_key_sha256", Value: statement.OperatorKeySHA256},
			{Key: "security_key_sha256", Value: statement.SecurityKeySHA256},
			{Key: "review_issue", Value: statement.ReviewIssue},
			{Key: "evidence_sha256", Value: statement.EvidenceSHA256},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalDigest[:])},
			{Key: "authority_a_sha256", Value: hex.EncodeToString(aHash[:])},
			{Key: "authority_b_sha256", Value: hex.EncodeToString(bHash[:])},
			{Key: "approved_at", Value: time.Unix(statement.IssuedAt, 0).UTC()},
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
	if errors.Is(err, ErrRetirementDenied) {
		return ErrRetirementDenied
	}
	if errors.Is(err, ErrRetirementConflict) || mongo.IsDuplicateKeyError(err) {
		return ErrRetirementConflict
	}
	return ErrRetirementStore
}
