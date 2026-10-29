package pendingaccounts

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const disabledCredentialState = "credential-staged-disabled"

// StageDisabledCredential provisions one new Argon2id password hash only
// after the exact same two-reviewer attestation was used to review this
// staging reservation. The caller must be a trusted OFFLINE operator; this
// method does not authenticate a claimant or expose a login capability.
//
// The signed assertion is deliberately short-lived. MongoDB's atomic CAS
// prevents a second provisioning call from overwriting the staged secret.
func (s *Store) StageDisabledCredential(ctx context.Context, signed SignedReview, candidate string) error {
	if s == nil || s.accounts == nil || ctx == nil || ctx.Err() != nil ||
		len(s.reviewerA) != ed25519.PublicKeySize ||
		len(s.reviewerB) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if err := VerifyReview(signed, s.reviewerA, s.reviewerB, time.Now().UTC()); err != nil {
		return ErrInvalid
	}
	v := signed.Statement
	key, ok := normalizedUsername(v.LegacyUsername)
	if !ok {
		return ErrInvalid
	}
	encoded, err := password.HashNew(candidate)
	if err != nil {
		return ErrInvalid
	}
	filter := bson.D{
		{Key: "_id", Value: v.Subject},
		{Key: "environment", Value: "staging"},
		{Key: "state", Value: reviewedState},
		{Key: "source", Value: v.Source},
		{Key: "legacy_username", Value: v.LegacyUsername},
		{Key: "alias_key", Value: key},
		{Key: "review_ref", Value: v.ReviewRef},
		{Key: "reviewed_at", Value: time.Unix(v.ReviewedAt, 0).UTC()},
		{Key: "review_nonce", Value: v.Nonce},
		{Key: "evidence_sha256", Value: v.EvidenceSHA256},
		{Key: "credential_hash", Value: bson.D{{Key: "$exists", Value: false}}},
	}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "state", Value: disabledCredentialState},
		{Key: "credentials_disabled", Value: true},
		{Key: "credential_hash", Value: encoded},
		{Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)},
		{Key: "credential_provisioned_at", Value: time.Now().UTC()},
	}}}
	result, err := s.accounts.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.ModifiedCount != 1 {
		return ErrConflict
	}
	return nil
}

// There is intentionally no Activate, Authenticate, ChangePassword or
// IssueSession API. A future activation must also bind sessions to versioned
// credentials and a revocation-safe account state, tested across replicas.
