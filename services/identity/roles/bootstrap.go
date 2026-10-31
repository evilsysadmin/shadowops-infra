package roles

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
	roleBootstrapAction            = "bootstrap-role-signers"
	roleBootstrapDomain            = "shadowops-identity-role-signers-bootstrap-v1\n"
	roleBootstrapGenesisID         = "staging:bootstrap-role-signers"
	roleBootstrapMaxSignerLifetime = 30 * 24 * time.Hour
)

var (
	ErrRoleBootstrapDenied   = errors.New("offline staging role signer bootstrap denied")
	ErrRoleBootstrapConflict = errors.New("staging role signer policy already bootstrapped")
	ErrRoleBootstrapStore    = errors.New("staging role signer bootstrap store unavailable")
)

// The fixed action and domain cannot authorize suspension or another Identity
// product. The authorities are separately pinned OUTSIDE Mongo; the two
// proposed operational signers must prove possession of their private keys.
type RoleBootstrapStatement struct {
	Environment       string `json:"environment"`
	Action            string `json:"action"`
	OperatorPublicKey string `json:"operator_public_key"`
	SecurityPublicKey string `json:"security_public_key"`
	NotBefore         int64  `json:"not_before"`
	NotAfter          int64  `json:"not_after"`
	ReviewIssue       string `json:"review_issue"`
	EvidenceSHA256    string `json:"evidence_sha256"`
	Nonce             string `json:"nonce"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
}

type SignedRoleBootstrap struct {
	Statement           RoleBootstrapStatement
	AuthorityASignature []byte
	AuthorityBSignature []byte
	OperatorProof       []byte
	SecurityProof       []byte
}

func roleBootstrapPublicKey(value string) (ed25519.PublicKey, error) {
	if len(value) != 2*ed25519.PublicKeySize {
		return nil, ErrRoleBootstrapDenied
	}
	key, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(key) != value {
		return nil, ErrRoleBootstrapDenied
	}
	return ed25519.PublicKey(key), nil
}

func RoleBootstrapMessage(statement RoleBootstrapStatement) ([]byte, error) {
	if statement.Environment != "staging" || statement.Action != roleBootstrapAction ||
		!roleReviewIssue.MatchString(statement.ReviewIssue) ||
		!roleEvidenceHash.MatchString(statement.EvidenceSHA256) ||
		!roleApprovalNonce.MatchString(statement.Nonce) ||
		statement.IssuedAt < 1577836800 || statement.ExpiresAt > 4102444800 ||
		statement.ExpiresAt <= statement.IssuedAt ||
		statement.ExpiresAt-statement.IssuedAt > int64(roleApprovalTTL.Seconds()) ||
		statement.NotBefore < statement.IssuedAt ||
		statement.NotBefore > statement.ExpiresAt ||
		statement.NotAfter <= statement.NotBefore ||
		statement.NotAfter > 4102444800 ||
		statement.NotAfter-statement.NotBefore > int64(roleBootstrapMaxSignerLifetime.Seconds()) {
		return nil, ErrRoleBootstrapDenied
	}
	operator, err := roleBootstrapPublicKey(statement.OperatorPublicKey)
	if err != nil {
		return nil, ErrRoleBootstrapDenied
	}
	security, err := roleBootstrapPublicKey(statement.SecurityPublicKey)
	if err != nil || bytes.Equal(operator, security) {
		return nil, ErrRoleBootstrapDenied
	}
	body, err := json.Marshal(statement)
	if err != nil {
		return nil, ErrRoleBootstrapDenied
	}
	return append([]byte(roleBootstrapDomain), body...), nil
}

// StagingRoleBootstrapper is offline-only. A dedicated, independent bootstrap
// Mongo principal may INSERT one genesis journal entry and one signer policy
// but must not have privileges to modify accounts, sessions or app tokens.
type StagingRoleBootstrapper struct {
	client           *mongo.Client
	journal          *mongo.Collection
	policy           *mongo.Collection
	authorityA       ed25519.PublicKey
	authorityB       ed25519.PublicKey
	afterPolicyWrite func() error // test-only rollback injection
}

func NewStagingRoleBootstrapper(ctx context.Context, client *mongo.Client, authorityA, authorityB ed25519.PublicKey) (*StagingRoleBootstrapper, error) {
	if ctx == nil || ctx.Err() != nil || client == nil ||
		len(authorityA) != ed25519.PublicKeySize || len(authorityB) != ed25519.PublicKeySize ||
		bytes.Equal(authorityA, authorityB) {
		return nil, ErrRoleBootstrapDenied
	}
	db := client.Database(roleDatabase)
	journal := db.Collection(roleJournal, options.Collection().
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	if err := verifyRoleJournal(ctx, journal); err != nil {
		return nil, ErrRoleBootstrapStore
	}
	return &StagingRoleBootstrapper{
		client: client, journal: journal, policy: db.Collection(rolePolicy),
		authorityA: append(ed25519.PublicKey(nil), authorityA...),
		authorityB: append(ed25519.PublicKey(nil), authorityB...),
	}, nil
}

func (b *StagingRoleBootstrapper) verify(s SignedRoleBootstrap, now time.Time) error {
	if b == nil || now.IsZero() || len(b.authorityA) != ed25519.PublicKeySize ||
		len(b.authorityB) != ed25519.PublicKeySize || bytes.Equal(b.authorityA, b.authorityB) ||
		len(s.AuthorityASignature) != ed25519.SignatureSize ||
		len(s.AuthorityBSignature) != ed25519.SignatureSize ||
		len(s.OperatorProof) != ed25519.SignatureSize ||
		len(s.SecurityProof) != ed25519.SignatureSize {
		return ErrRoleBootstrapDenied
	}
	statement := s.Statement
	message, err := RoleBootstrapMessage(statement)
	if err != nil {
		return ErrRoleBootstrapDenied
	}
	epoch := now.UTC().Unix()
	if epoch < statement.IssuedAt-int64(roleApprovalSkew.Seconds()) ||
		epoch >= statement.ExpiresAt || epoch >= statement.NotAfter {
		return ErrRoleBootstrapDenied
	}
	operator, err := roleBootstrapPublicKey(statement.OperatorPublicKey)
	if err != nil {
		return ErrRoleBootstrapDenied
	}
	security, err := roleBootstrapPublicKey(statement.SecurityPublicKey)
	if err != nil ||
		bytes.Equal(operator, b.authorityA) || bytes.Equal(operator, b.authorityB) ||
		bytes.Equal(security, b.authorityA) || bytes.Equal(security, b.authorityB) {
		return ErrRoleBootstrapDenied
	}
	if !ed25519.Verify(b.authorityA, message, s.AuthorityASignature) ||
		!ed25519.Verify(b.authorityB, message, s.AuthorityBSignature) ||
		!ed25519.Verify(operator, message, s.OperatorProof) ||
		!ed25519.Verify(security, message, s.SecurityProof) {
		return ErrRoleBootstrapDenied
	}
	return nil
}

// Bootstrap records the genesis and its exact policy atomically with majority
// write concern. Fixed genesis _id prevents re-enrolment even with a fresh
// nonce after the policy is deleted. Approval is checked again in the txn.
func (b *StagingRoleBootstrapper) Bootstrap(ctx context.Context, signed SignedRoleBootstrap) error {
	if b == nil || b.client == nil || b.journal == nil || b.policy == nil ||
		ctx == nil || ctx.Err() != nil {
		return ErrRoleBootstrapDenied
	}
	if err := b.verify(signed, time.Now().UTC()); err != nil {
		return ErrRoleBootstrapDenied
	}
	statement := signed.Statement
	message, err := RoleBootstrapMessage(statement)
	if err != nil {
		return ErrRoleBootstrapDenied
	}
	operator, _ := roleBootstrapPublicKey(statement.OperatorPublicKey)
	security, _ := roleBootstrapPublicKey(statement.SecurityPublicKey)
	operatorHash := sha256.Sum256(operator)
	securityHash := sha256.Sum256(security)
	authorityAHash := sha256.Sum256(b.authorityA)
	authorityBHash := sha256.Sum256(b.authorityB)
	approvalHash := sha256.Sum256(message)
	session, err := b.client.StartSession()
	if err != nil {
		return ErrRoleBootstrapStore
	}
	defer session.EndSession(context.Background())
	transaction := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetReadPreference(readpref.Primary()).SetWriteConcern(writeconcern.Majority())
	_, err = session.WithTransaction(ctx, func(tx context.Context) (any, error) {
		now := time.Now().UTC()
		if err := b.verify(signed, now); err != nil {
			return nil, ErrRoleBootstrapDenied
		}
		_, err := b.journal.InsertOne(tx, bson.D{
			{Key: "_id", Value: roleBootstrapGenesisID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: roleBootstrapAction},
			{Key: "nonce", Value: statement.Nonce},
			{Key: "generation", Value: int64(1)},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(operatorHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityHash[:])},
			{Key: "authority_a_sha256", Value: hex.EncodeToString(authorityAHash[:])},
			{Key: "authority_b_sha256", Value: hex.EncodeToString(authorityBHash[:])},
			{Key: "approval_sha256", Value: hex.EncodeToString(approvalHash[:])},
			{Key: "review_issue", Value: statement.ReviewIssue},
			{Key: "evidence_sha256", Value: statement.EvidenceSHA256},
			{Key: "not_before", Value: time.Unix(statement.NotBefore, 0).UTC()},
			{Key: "not_after", Value: time.Unix(statement.NotAfter, 0).UTC()},
			{Key: "executed_at", Value: now},
		})
		if err != nil {
			return nil, err
		}
		_, err = b.policy.InsertOne(tx, bson.D{
			{Key: "_id", Value: rolePolicyID},
			{Key: "environment", Value: "staging"},
			{Key: "action", Value: SetRoleAction},
			{Key: "state", Value: "active"},
			{Key: "generation", Value: int64(1)},
			{Key: "operator_key_sha256", Value: hex.EncodeToString(operatorHash[:])},
			{Key: "security_key_sha256", Value: hex.EncodeToString(securityHash[:])},
			{Key: "not_before", Value: time.Unix(statement.NotBefore, 0).UTC()},
			{Key: "not_after", Value: time.Unix(statement.NotAfter, 0).UTC()},
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
	}, transaction)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRoleBootstrapDenied) {
		return ErrRoleBootstrapDenied
	}
	if mongo.IsDuplicateKeyError(err) {
		return ErrRoleBootstrapConflict
	}
	return ErrRoleBootstrapStore
}
