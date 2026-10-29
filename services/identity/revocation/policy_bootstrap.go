package revocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	bootstrapAction  = "bootstrap-staging-signers"
	bootstrapDomain  = "shadowops-identity-signer-bootstrap-v1\n"
	bootstrapEventID = "staging:bootstrap-signer-policy"
)

var (
	ErrBootstrapDenied   = errors.New("offline staging signer bootstrap denied")
	ErrBootstrapConflict = errors.New("staging signer bootstrap already completed or policy exists")
	ErrBootstrapStore    = errors.New("staging signer bootstrap store unavailable")
)

// BootstrapStatement requests ONE first-generation staging administrative
// signer policy. Governance keys are trusted out-of-band, never enrolled by
// this method; operational signers must independently prove key possession.
type BootstrapStatement struct {
	Environment          string `json:"environment"`
	Action               string `json:"action"`
	NewOperatorPublicKey string `json:"new_operator_public_key"`
	NewSecurityPublicKey string `json:"new_security_public_key"`
	NotBefore            int64  `json:"not_before"`
	NotAfter             int64  `json:"not_after"`
	ReviewIssue          string `json:"review_issue"`
	EvidenceSHA256       string `json:"evidence_sha256"`
	Nonce                string `json:"nonce"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
}

type SignedBootstrap struct {
	Statement           BootstrapStatement
	AuthorityASignature []byte
	AuthorityBSignature []byte
	NewOperatorProof    []byte
	NewSecurityProof    []byte
}

func BootstrapMessage(v BootstrapStatement) ([]byte, error) {
	if v.Environment != "staging" || v.Action != bootstrapAction ||
		!approvalIssue.MatchString(v.ReviewIssue) ||
		!approvalSHA256.MatchString(v.EvidenceSHA256) ||
		!approvalNonce.MatchString(v.Nonce) ||
		v.IssuedAt < 1577836800 || v.ExpiresAt > 4102444800 ||
		v.ExpiresAt <= v.IssuedAt || v.ExpiresAt-v.IssuedAt > int64(approvalLifetime.Seconds()) ||
		v.NotBefore < v.IssuedAt || v.NotBefore > v.ExpiresAt ||
		v.NotAfter <= v.NotBefore || v.NotAfter > 4102444800 ||
		v.NotAfter-v.NotBefore > int64(maxRecoveredSignerLifetime.Seconds()) {
		return nil, ErrBootstrapDenied
	}
	operator, err := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	if err != nil {
		return nil, ErrBootstrapDenied
	}
	security, err := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	if err != nil || bytes.Equal(operator, security) {
		return nil, ErrBootstrapDenied
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, ErrBootstrapDenied
	}
	return append([]byte(bootstrapDomain), raw...), nil
}

// StagingSignerBootstrapper is a non-networked, one-time trust ceremony.
// The caller must pin governance keys independently outside MongoDB, vet
// reviewers, isolate DB write privileges and retain/offsite-backup the audit.
type StagingSignerBootstrapper struct {
	governance       *StagingPolicyRetirer
	afterPolicyWrite func() error // synthetic rollback injection only
}

func NewStagingSignerBootstrapper(ctx context.Context, client *mongo.Client, authorityA, authorityB ed25519.PublicKey) (*StagingSignerBootstrapper, error) {
	governance, err := NewStagingPolicyRetirer(ctx, client, authorityA, authorityB)
	if err != nil {
		return nil, err
	}
	return &StagingSignerBootstrapper{governance: governance}, nil
}

func (b *StagingSignerBootstrapper) verify(s SignedBootstrap, now time.Time) error {
	if b == nil || b.governance == nil ||
		len(b.governance.authorityA) != ed25519.PublicKeySize ||
		len(b.governance.authorityB) != ed25519.PublicKeySize ||
		bytes.Equal(b.governance.authorityA, b.governance.authorityB) ||
		now.IsZero() || len(s.AuthorityASignature) != ed25519.SignatureSize ||
		len(s.AuthorityBSignature) != ed25519.SignatureSize ||
		len(s.NewOperatorProof) != ed25519.SignatureSize ||
		len(s.NewSecurityProof) != ed25519.SignatureSize {
		return ErrBootstrapDenied
	}
	v := s.Statement
	message, err := BootstrapMessage(v)
	if err != nil {
		return ErrBootstrapDenied
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < v.IssuedAt-int64(approvalClockSkew.Seconds()) ||
		nowUnix >= v.ExpiresAt || nowUnix >= v.NotAfter {
		return ErrBootstrapDenied
	}
	op, err := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	if err != nil {
		return ErrBootstrapDenied
	}
	sec, err := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	if err != nil {
		return ErrBootstrapDenied
	}
	if bytes.Equal(op, b.governance.authorityA) ||
		bytes.Equal(op, b.governance.authorityB) ||
		bytes.Equal(sec, b.governance.authorityA) ||
		bytes.Equal(sec, b.governance.authorityB) {
		return ErrBootstrapDenied
	}
	if !ed25519.Verify(b.governance.authorityA, message, s.AuthorityASignature) ||
		!ed25519.Verify(b.governance.authorityB, message, s.AuthorityBSignature) ||
		!ed25519.Verify(op, message, s.NewOperatorProof) ||
		!ed25519.Verify(sec, message, s.NewSecurityProof) {
		return ErrBootstrapDenied
	}
	return nil
}

// Bootstrap creates a version-1 policy AND its immutable-intended genesis
// event in one snapshot/majority transaction. The fixed journal _id prevents
// a second bootstrap even if someone later deletes the policy document.
// Missing/forged governance trust anchors or journal deletion are external
// threats; never grant arbitrary DB writes to this library's callers.
func (b *StagingSignerBootstrapper) Bootstrap(ctx context.Context, signed SignedBootstrap) error {
	if b == nil || b.governance == nil || b.governance.client == nil ||
		b.governance.policy == nil || b.governance.journal == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrBootstrapDenied
	}
	if err := b.verify(signed, time.Now().UTC()); err != nil {
		return ErrBootstrapDenied
	}
	v := signed.Statement
	message, err := BootstrapMessage(v)
	if err != nil {
		return ErrBootstrapDenied
	}
	op, _ := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	sec, _ := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	opHash := sha256.Sum256(op)
	secHash := sha256.Sum256(sec)
	govAHash := sha256.Sum256(b.governance.authorityA)
	govBHash := sha256.Sum256(b.governance.authorityB)
	approvalHash := sha256.Sum256(message)

	sess, err := b.governance.client.StartSession()
	if err != nil {
		return ErrBootstrapStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		now := time.Now().UTC()
		if err := b.verify(signed, now); err != nil {
			return nil, ErrBootstrapDenied
		}
		// Deterministic genesis ID is deliberately not scoped by nonce:
		// different freshly signed bootstrap requests still conflict.
		_, err := b.governance.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: bootstrapEventID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: bootstrapAction},
			{Key: "nonce", Value: v.Nonce},
			{Key: "generation", Value: int64(1)},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(opHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(secHash[:])},
			{Key: "authority_a_sha256", Value: hex.EncodeToString(govAHash[:])},
			{Key: "authority_b_sha256", Value: hex.EncodeToString(govBHash[:])},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalHash[:])},
			{Key: "review_issue", Value: v.ReviewIssue},
			{Key: "evidence_sha256", Value: v.EvidenceSHA256},
			{Key: "not_before", Value: time.Unix(v.NotBefore, 0).UTC()},
			{Key: "not_after", Value: time.Unix(v.NotAfter, 0).UTC()},
			{Key: "executed_at", Value: now},
		})
		if err != nil {
			return nil, err
		}
		_, err = b.governance.policy.InsertOne(tx, bson.D{
			{Key: "_id", Value: signerPolicyID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: SuspendAndRevokeAction},
			{Key: "state", Value: "active"},
			{Key: "generation", Value: int64(1)},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(opHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(secHash[:])},
			{Key: "not_before", Value: time.Unix(v.NotBefore, 0).UTC()},
			{Key: "not_after", Value: time.Unix(v.NotAfter, 0).UTC()},
			{Key: "use_fence", Value: int64(0)},
		})
		if err != nil {
			return nil, err
		}
		if b.afterPolicyWrite != nil {
			if err := b.afterPolicyWrite(); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}, txn)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrBootstrapDenied) {
		return ErrBootstrapDenied
	}
	if mongo.IsDuplicateKeyError(err) {
		return ErrBootstrapConflict
	}
	return ErrBootstrapStore
}
