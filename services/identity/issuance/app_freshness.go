package issuance

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// Retain the original collection name and CKA digest namespace: existing
// staged CKA bindings remain valid. Every lookup is still audience-bound.
const appTokenCollection = "staging_cka_tokens"
const stagingIssuerURL = "https://id-staging.shadowops.dpdns.org"
const freshnessDeadline = 2 * time.Second

type appTokenRecord struct {
	ID             string    `bson:"_id"`
	Issuer         string    `bson:"issuer"`
	Audience       string    `bson:"audience"`
	Subject        string    `bson:"subject"`
	SessionVersion int64     `bson:"session_version"`
	SessionDigest  string    `bson:"session_digest"`
	IssuedAt       time.Time `bson:"issued_at"`
	ExpiresAt      time.Time `bson:"expires_at"`
	Active         bool      `bson:"active"`
}

func tokenDigestFor(application Application, jti string) string {
	digest := sha256.Sum256([]byte("shadowops-app-token-v1:staging:" + string(application) + ":" + jti))
	return hex.EncodeToString(digest[:])
}

// SessionFreshnessEvidence matches the CKA consumer's strictly bound evidence.
// It is a point-in-time observation, NOT an authorization lease or a JWT verifier.
// No HTTP route publishes this type. A future transport must authenticate the
// calling service and bind its fixed issuer/audience independently of the user.
type SessionFreshnessEvidence struct {
	Issuer         string `json:"issuer"`
	Subject        string `json:"subject"`
	SessionVersion int64  `json:"session_version"`
	TokenJTI       string `json:"token_jti"`
	CheckedAt      int64  `json:"checked_at"`
	AccountActive  bool   `json:"account_active"`
	SessionActive  bool   `json:"session_active"`
	TokenActive    bool   `json:"token_active"`
}

// ApplicationFreshnessEvidence must match the consumer's fixed audience.
type ApplicationFreshnessEvidence struct {
	SessionFreshnessEvidence
	Audience Application `json:"audience"`
}

// StagingAppFreshness requires no signing key. It is an internal, staging-only
// authority bound to one configured application, not an enabled login path.
// The caller MUST first verify the JWT's signature, issuer, audience and times.
type StagingAppFreshness struct {
	application Application
	client      *mongo.Client
	accounts    *mongo.Collection
	sessions    session.Store
}

func NewStagingAppFreshness(issuer *Issuer, application Application) (*StagingAppFreshness, error) {
	if issuer == nil || issuer.client == nil || issuer.accounts == nil || issuer.sessions == nil || !application.valid() {
		return nil, ErrDenied
	}
	return &StagingAppFreshness{application: application, client: issuer.client, accounts: issuer.accounts, sessions: issuer.sessions}, nil
}

// Check validates a committed JTI binding and fences the exact account, session
// and token documents in one snapshot/majority transaction. Refresh, logout,
// account suspension and token deactivation conflict with these same documents.
// After any of those operations completes, a new check cannot report active.
// A concurrent check can order before revocation; its evidence is never a promise
// about future requests. Consumers must recheck every protected operation.
func (c *StagingAppFreshness) Check(ctx context.Context, subject string, version int64, jti string) (ApplicationFreshnessEvidence, error) {
	deny := ApplicationFreshnessEvidence{}
	if c == nil || c.client == nil || c.accounts == nil || c.sessions == nil || !c.application.valid() || ctx == nil || ctx.Err() != nil ||
		!uuidV4.MatchString(subject) || version <= 0 || len(jti) != 22 {
		return deny, ErrDenied
	}
	raw, err := base64.RawURLEncoding.DecodeString(jti)
	if err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != jti {
		return deny, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, freshnessDeadline)
	defer cancel()
	sess, err := c.client.StartSession()
	if err != nil {
		return deny, ErrStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	var checked time.Time
	var expires time.Time
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		checked = time.Now().UTC()
		var record appTokenRecord
		tokens := c.client.Database(stagingDatabase).Collection(appTokenCollection)
		if err := tokens.FindOne(tx, bson.D{{Key: "_id", Value: tokenDigestFor(c.application, jti)}}).Decode(&record); err != nil {
			return nil, err
		}
		if record.Issuer != stagingIssuerURL || record.Audience != string(c.application) || record.Subject != subject ||
			record.SessionVersion != version || !record.Active || record.IssuedAt.After(checked) ||
			!checked.Before(record.ExpiresAt) || !record.IssuedAt.Before(record.ExpiresAt) ||
			record.ExpiresAt.Sub(record.IssuedAt) > appTokenLifetime {
			return nil, ErrDenied
		}
		digestBytes, err := hex.DecodeString(record.SessionDigest)
		if err != nil || len(digestBytes) != 32 || hex.EncodeToString(digestBytes) != record.SessionDigest {
			return nil, ErrDenied
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		rec, exists, err := c.sessions.Get(tx, "staging", digest)
		if err != nil {
			return nil, err
		}
		if !exists || rec.Subject != subject || rec.SessionVersion != version || rec.Environment != "staging" || rec.Digest != digest ||
			!rec.IssuedAt.Before(rec.ExpiresAt) || rec.IssuedAt.After(checked.Add(30*time.Second)) ||
			rec.ExpiresAt.Sub(rec.IssuedAt) > session.Lifetime || !checked.Before(rec.ExpiresAt) || record.ExpiresAt.After(rec.ExpiresAt) {
			return nil, ErrDenied
		}
		// Real writes prevent a stale read-only snapshot from bypassing a completed
		// account suspension, source-session deletion/rotation, or token deactivation.
		fences := []struct {
			col    *mongo.Collection
			filter bson.D
		}{
			{c.accounts, bson.D{{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"}, {Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}, {Key: "session_version", Value: version}}},
			{c.client.Database(stagingDatabase).Collection("sessions"), bson.D{{Key: "environment", Value: "staging"}, {Key: "digest", Value: record.SessionDigest}, {Key: "subject", Value: subject}, {Key: "session_version", Value: version}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: checked}}}}},
			{tokens, bson.D{{Key: "_id", Value: record.ID}, {Key: "active", Value: true}}},
		}
		for _, fence := range fences {
			result, err := fence.col.UpdateOne(tx, fence.filter, bson.D{{Key: "$inc", Value: bson.D{{Key: "freshness_fence", Value: int64(1)}}}})
			if err != nil {
				return nil, err
			}
			if result.ModifiedCount != 1 {
				return nil, ErrDenied
			}
		}
		expires = record.ExpiresAt
		return nil, nil
	}, txn)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, mongo.ErrNoDocuments) {
			return deny, ErrDenied
		}
		return deny, ErrStore
	}
	now := time.Now().UTC()
	if ctx.Err() != nil || now.Before(checked) || now.Sub(checked) > freshnessDeadline || !now.Before(expires) {
		return deny, ErrStore
	}
	return ApplicationFreshnessEvidence{Audience: c.application, SessionFreshnessEvidence: SessionFreshnessEvidence{Issuer: stagingIssuerURL, Subject: subject, SessionVersion: version, TokenJTI: jti, CheckedAt: checked.Unix(), AccountActive: true, SessionActive: true, TokenActive: true}}, nil
}
