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
	recoveryAction             = "recover-revoked-signers"
	recoveryDomain             = "shadowops-identity-signer-recovery-v1\n"
	maxRecoveredSignerLifetime = 30 * 24 * time.Hour
)

var (
	ErrRecoveryDenied   = errors.New("offline staging signer recovery denied")
	ErrRecoveryConflict = errors.New("offline staging signer recovery conflict")
	ErrRecoveryStore    = errors.New("offline staging signer recovery store unavailable")
)

// RecoveryStatement is a ONE-WAY replacement of a previously revoked
// operational signer pair. It is not an initial trust bootstrap. The prior
// generation and key fingerprints are matched against a committed retirement
// journal event; the new keys must be different and prove private-key control.
type RecoveryStatement struct {
	Environment              string `json:"environment"`
	Action                   string `json:"action"`
	RevokedGeneration        int64  `json:"revoked_generation"`
	RevokedOperatorKeySHA256 string `json:"revoked_operator_key_sha256"`
	RevokedSecurityKeySHA256 string `json:"revoked_security_key_sha256"`
	NewOperatorPublicKey     string `json:"new_operator_public_key"`
	NewSecurityPublicKey     string `json:"new_security_public_key"`
	NotBefore                int64  `json:"not_before"`
	NotAfter                 int64  `json:"not_after"`
	ReviewIssue              string `json:"review_issue"`
	EvidenceSHA256           string `json:"evidence_sha256"`
	Nonce                    string `json:"nonce"`
	IssuedAt                 int64  `json:"issued_at"`
	ExpiresAt                int64  `json:"expires_at"`
}

type SignedRecovery struct {
	Statement           RecoveryStatement
	AuthorityASignature []byte
	AuthorityBSignature []byte
	NewOperatorProof    []byte
	NewSecurityProof    []byte
}

func decodeRecoveryPublicKey(value string) (ed25519.PublicKey, error) {
	if !approvalSHA256.MatchString(value) {
		return nil, ErrRecoveryDenied
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrRecoveryDenied
	}
	return ed25519.PublicKey(key), nil
}

// RecoveryMessage has its own domain, fixed field order and strict validity
// bounds. All four signatures (governance approval + new-key possession) cover
// these SAME bytes. Fingerprints are SHA-256 of raw Ed25519 public keys.
func RecoveryMessage(v RecoveryStatement) ([]byte, error) {
	if v.Environment != "staging" || v.Action != recoveryAction ||
		v.RevokedGeneration < 2 || v.RevokedGeneration >= math.MaxInt64 ||
		!approvalSHA256.MatchString(v.RevokedOperatorKeySHA256) ||
		!approvalSHA256.MatchString(v.RevokedSecurityKeySHA256) ||
		v.RevokedOperatorKeySHA256 == v.RevokedSecurityKeySHA256 ||
		!approvalIssue.MatchString(v.ReviewIssue) ||
		!approvalSHA256.MatchString(v.EvidenceSHA256) ||
		!approvalNonce.MatchString(v.Nonce) ||
		v.IssuedAt < 1577836800 || v.ExpiresAt > 4102444800 ||
		v.ExpiresAt <= v.IssuedAt || v.ExpiresAt-v.IssuedAt > int64(approvalLifetime.Seconds()) ||
		v.NotBefore < v.IssuedAt || v.NotBefore > v.ExpiresAt ||
		v.NotAfter <= v.NotBefore || v.NotAfter > 4102444800 ||
		v.NotAfter-v.NotBefore > int64(maxRecoveredSignerLifetime.Seconds()) {
		return nil, ErrRecoveryDenied
	}
	operator, err := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	if err != nil {
		return nil, ErrRecoveryDenied
	}
	security, err := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	if err != nil || bytes.Equal(operator, security) {
		return nil, ErrRecoveryDenied
	}
	operatorDigest := sha256.Sum256(operator)
	securityDigest := sha256.Sum256(security)
	for _, old := range []string{v.RevokedOperatorKeySHA256, v.RevokedSecurityKeySHA256} {
		if old == hex.EncodeToString(operatorDigest[:]) || old == hex.EncodeToString(securityDigest[:]) {
			return nil, ErrRecoveryDenied
		}
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, ErrRecoveryDenied
	}
	message := append([]byte(recoveryDomain), payload...)
	return message, nil
}

// StagingPolicyRecoverer composes the SAME independently pinned governance
// authorities and permanent journal as the emergency retirement primitive.
// It does not enroll human identities or provision live signing credentials.
type StagingPolicyRecoverer struct {
	retirer          *StagingPolicyRetirer
	afterPolicyWrite func() error // deterministic integration-test rollback only
}

func NewStagingPolicyRecoverer(ctx context.Context, client *mongo.Client, authorityA, authorityB ed25519.PublicKey) (*StagingPolicyRecoverer, error) {
	retirer, err := NewStagingPolicyRetirer(ctx, client, authorityA, authorityB)
	if err != nil {
		return nil, err
	}
	return &StagingPolicyRecoverer{retirer: retirer}, nil
}

func (r *StagingPolicyRecoverer) verify(s SignedRecovery, now time.Time) error {
	if r == nil || r.retirer == nil || r.retirer.client == nil ||
		len(r.retirer.authorityA) != ed25519.PublicKeySize ||
		len(r.retirer.authorityB) != ed25519.PublicKeySize ||
		bytes.Equal(r.retirer.authorityA, r.retirer.authorityB) || now.IsZero() ||
		len(s.AuthorityASignature) != ed25519.SignatureSize ||
		len(s.AuthorityBSignature) != ed25519.SignatureSize ||
		len(s.NewOperatorProof) != ed25519.SignatureSize ||
		len(s.NewSecurityProof) != ed25519.SignatureSize {
		return ErrRecoveryDenied
	}
	v := s.Statement
	message, err := RecoveryMessage(v)
	if err != nil {
		return ErrRecoveryDenied
	}
	epoch := now.UTC().Unix()
	if epoch < v.IssuedAt-int64(approvalClockSkew.Seconds()) ||
		epoch >= v.ExpiresAt || epoch >= v.NotAfter {
		return ErrRecoveryDenied
	}
	operator, err := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	if err != nil {
		return ErrRecoveryDenied
	}
	security, err := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	if err != nil {
		return ErrRecoveryDenied
	}
	for _, gov := range []ed25519.PublicKey{r.retirer.authorityA, r.retirer.authorityB} {
		govHash := sha256.Sum256(gov)
		if bytes.Equal(gov, operator) || bytes.Equal(gov, security) ||
			hex.EncodeToString(govHash[:]) == v.RevokedOperatorKeySHA256 ||
			hex.EncodeToString(govHash[:]) == v.RevokedSecurityKeySHA256 {
			return ErrRecoveryDenied
		}
	}
	if !ed25519.Verify(r.retirer.authorityA, message, s.AuthorityASignature) ||
		!ed25519.Verify(r.retirer.authorityB, message, s.AuthorityBSignature) ||
		!ed25519.Verify(operator, message, s.NewOperatorProof) ||
		!ed25519.Verify(security, message, s.NewSecurityProof) {
		return ErrRecoveryDenied
	}
	return nil
}

// Recover replaces the keys only from an audited, already-REVOKED policy at
// the exact post-retirement generation. The matching retirement event is read
// inside the same snapshot/majority transaction and bound to revoked_at. The
// live policy write conflicts with concurrent retirements and suspensions.
// It cannot seed a missing policy or re-activate an already active one.
func (r *StagingPolicyRecoverer) Recover(ctx context.Context, signed SignedRecovery) error {
	if r == nil || r.retirer == nil || r.retirer.client == nil ||
		r.retirer.policy == nil || r.retirer.journal == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrRecoveryDenied
	}
	if err := r.verify(signed, time.Now().UTC()); err != nil {
		return ErrRecoveryDenied
	}
	v := signed.Statement
	message, err := RecoveryMessage(v)
	if err != nil {
		return ErrRecoveryDenied
	}
	approvalHash := sha256.Sum256(message)
	newOp, _ := decodeRecoveryPublicKey(v.NewOperatorPublicKey)
	newSec, _ := decodeRecoveryPublicKey(v.NewSecurityPublicKey)
	opHash := sha256.Sum256(newOp)
	secHash := sha256.Sum256(newSec)
	govAHash := sha256.Sum256(r.retirer.authorityA)
	govBHash := sha256.Sum256(r.retirer.authorityB)
	activationFrom := time.Unix(v.NotBefore, 0).UTC()
	activationUntil := time.Unix(v.NotAfter, 0).UTC()

	session, err := r.retirer.client.StartSession()
	if err != nil {
		return ErrRecoveryStore
	}
	defer session.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = session.WithTransaction(ctx, func(tx context.Context) (any, error) {
		now := time.Now().UTC()
		if err := r.verify(signed, now); err != nil {
			return nil, ErrRecoveryDenied
		}
		// A synthetic "revoked" state without its matching committed
		// retirement journal event is not a valid recovery source.
		var previous struct {
			ExecutedAt time.Time `bson:"executed_at"`
			Nonce      string    `bson:"nonce"`
		}
		lookup := bson.D{
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: retirementAction},
			{Key: "generation", Value: v.RevokedGeneration - 1},
			{Key: "operator_key_sha256", Value: v.RevokedOperatorKeySHA256},
			{Key: "security_key_sha256", Value: v.RevokedSecurityKeySHA256},
		}
		if err := r.retirer.journal.FindOne(tx, lookup).Decode(&previous); err != nil ||
			previous.ExecutedAt.IsZero() || !approvalNonce.MatchString(previous.Nonce) {
			return nil, ErrRecoveryDenied
		}
		result, err := r.retirer.policy.UpdateOne(tx, bson.D{
			{Key: "_id", Value: signerPolicyID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: SuspendAndRevokeAction},
			{Key: "state", Value: "revoked"},
			{Key: "generation", Value: v.RevokedGeneration},
			{Key: "operator_key_sha256", Value: v.RevokedOperatorKeySHA256},
			{Key: "security_key_sha256", Value: v.RevokedSecurityKeySHA256},
			{Key: "revoked_at", Value: previous.ExecutedAt},
		}, bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "state", Value: "active"},
				{Key: "operator_key_sha256", Value: hex.EncodeToString(opHash[:])},
				{Key: "security_key_sha256", Value: hex.EncodeToString(secHash[:])},
				{Key: "not_before", Value: activationFrom},
				{Key: "not_after", Value: activationUntil},
			}},
			{Key: "$inc", Value: bson.D{{Key: "generation", Value: int64(1)}}},
			{Key: "$unset", Value: bson.D{{Key: "revoked_at", Value: ""}}},
		})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrRecoveryConflict
		}
		if r.afterPolicyWrite != nil {
			if err := r.afterPolicyWrite(); err != nil {
				return nil, err
			}
		}
		_, err = r.retirer.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: "staging:" + recoveryAction + ":" + v.Nonce},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: recoveryAction},
			{Key: "nonce", Value: v.Nonce},
			{Key: "revoked_generation", Value: v.RevokedGeneration},
			{Key: "activated_generation", Value: v.RevokedGeneration + 1},
			{Key: "prior_retirement_nonce", Value: previous.Nonce},
			{Key: "old_operator_key_sha256", Value: v.RevokedOperatorKeySHA256},
			{Key: "old_security_key_sha256", Value: v.RevokedSecurityKeySHA256},
			{Key: "new_operator_key_sha256", Value: hex.EncodeToString(opHash[:])},
			{Key: "new_security_key_sha256", Value: hex.EncodeToString(secHash[:])},
			{Key: "authority_a_sha256", Value: hex.EncodeToString(govAHash[:])},
			{Key: "authority_b_sha256", Value: hex.EncodeToString(govBHash[:])},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalHash[:])},
			{Key: "evidence_sha256", Value: v.EvidenceSHA256},
			{Key: "review_issue", Value: v.ReviewIssue},
			{Key: "not_before", Value: activationFrom},
			{Key: "not_after", Value: activationUntil},
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
	if errors.Is(err, ErrRecoveryDenied) {
		return ErrRecoveryDenied
	}
	if errors.Is(err, ErrRecoveryConflict) || mongo.IsDuplicateKeyError(err) {
		return ErrRecoveryConflict
	}
	return ErrRecoveryStore
}
