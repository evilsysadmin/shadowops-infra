package issuance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/core"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	ckaAudience         = "cka-simulator"
	ckaPoCTokenLifetime = 2 * time.Minute
)

// CKAPoCSigner is an OFFLINE ONLY, session-bound staging JWT bridge.
// No HTTP endpoint constructs it. Its output proves Go/Python contract
// interoperability, NOT current account authorization at a future time.
// Product access needs an independent revocation check on every request.
type CKAPoCSigner struct {
	issuer   *Issuer
	identity *core.Core
	private  ed25519.PrivateKey
	kid      string
}

// NewCKAPoCSigner must receive a real staging Issuer with an actual MongoDB
// session store, and a separately held staging key. Neither a user-supplied
// subject nor an arbitrary application audience can be provided at signing.
func NewCKAPoCSigner(issuer *Issuer, seed []byte) (*CKAPoCSigner, error) {
	if issuer == nil || issuer.client == nil || issuer.accounts == nil ||
		issuer.sessions == nil || len(seed) != ed25519.SeedSize {
		return nil, ErrDenied
	}
	id, err := core.New("staging", seed)
	if err != nil {
		return nil, ErrDenied
	}
	jwks, err := id.JWKS()
	if err != nil {
		return nil, ErrDenied
	}
	var keys core.KeySet
	if err := json.Unmarshal(jwks, &keys); err != nil || len(keys.Keys) != 1 {
		return nil, ErrDenied
	}
	return &CKAPoCSigner{
		issuer: issuer, identity: id,
		private: ed25519.NewKeyFromSeed(seed), kid: keys.Keys[0].Kid,
	}, nil
}

func (s *CKAPoCSigner) JWKS() ([]byte, error) {
	if s == nil || s.identity == nil {
		return nil, ErrDenied
	}
	return s.identity.JWKS()
}

type ckaPOCClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Sv  int64  `json:"sv"`
	Jti string `json:"jti"`
}

// IssuePoCToken verifies the opaque session in a Mongo snapshot/majority
// transaction, then WRITES the same eligible account document modified by
// revocation. A concurrent suspension must win or conflict at the commit.
// A token already issued may remain cryptographically valid for up to two
// minutes after later revocation; CKA must NOT use this as user authorization
// until live session-version checks and access controls are wired.
func (s *CKAPoCSigner) IssuePoCToken(ctx context.Context, handle string) (string, error) {
	if s == nil || s.issuer == nil || s.identity == nil ||
		len(s.private) != ed25519.PrivateKeySize || s.kid == "" ||
		ctx == nil || ctx.Err() != nil {
		return "", ErrDenied
	}
	digest, ok := stagingHandleDigest(handle)
	if !ok {
		return "", ErrDenied
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrStore
	}
	sess, err := s.issuer.client.StartSession()
	if err != nil {
		return "", ErrStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	var signedClaims ckaPOCClaims
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		rec, exists, err := s.issuer.sessions.Get(tx, "staging", digest)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if !exists || rec.Digest != digest || rec.Environment != "staging" ||
			!uuidV4.MatchString(rec.Subject) || rec.SessionVersion <= 0 ||
			!rec.IssuedAt.Before(rec.ExpiresAt) ||
			rec.IssuedAt.After(now.Add(30*time.Second)) ||
			rec.ExpiresAt.Sub(rec.IssuedAt) > session.Lifetime ||
			!now.Before(rec.ExpiresAt) {
			return nil, ErrDenied
		}
		result, err := s.issuer.accounts.UpdateOne(tx, bson.D{
			{Key: "_id", Value: rec.Subject},
			{Key: "environment", Value: "staging"},
			{Key: "state", Value: "active"},
			{Key: "credentials_disabled", Value: false},
			{Key: "session_version", Value: rec.SessionVersion},
		}, bson.D{{Key: "$inc", Value: bson.D{{Key: "login_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrDenied
		}
		if s.issuer.afterFence != nil {
			if err := s.issuer.afterFence(); err != nil {
				return nil, err
			}
		}
		expires := now.Add(ckaPoCTokenLifetime)
		if rec.ExpiresAt.Before(expires) {
			expires = rec.ExpiresAt
		}
		if expires.Unix() <= now.Unix() {
			return nil, ErrDenied
		}
		signedClaims = ckaPOCClaims{
			Iss: s.identity.Issuer(), Aud: ckaAudience, Sub: rec.Subject,
			Iat: now.Unix(), Nbf: now.Unix(), Exp: expires.Unix(),
			Sv: rec.SessionVersion, Jti: base64.RawURLEncoding.EncodeToString(nonce[:]),
		}
		// Register the exact token-to-session binding in the same transaction.
		// Neither raw JWTs, raw JTIs nor opaque handles are persisted.
		_, err = s.issuer.client.Database(stagingDatabase).Collection(appTokenCollection).InsertOne(tx, appTokenRecord{
			ID: tokenDigest(signedClaims.Jti), Issuer: signedClaims.Iss, Audience: ckaAudience,
			Subject: rec.Subject, SessionVersion: rec.SessionVersion,
			SessionDigest: hex.EncodeToString(digest[:]),
			IssuedAt:      time.Unix(signedClaims.Iat, 0).UTC(),
			ExpiresAt:     time.Unix(signedClaims.Exp, 0).UTC(), Active: true,
		})
		return nil, err
	}, txn)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	// Sign only after the majority transaction commits. No secret is
	// written to MongoDB, HTTP, logs or the repository.
	head, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{Alg: "EdDSA", Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", ErrStore
	}
	body, err := json.Marshal(signedClaims)
	if err != nil {
		return "", ErrStore
	}
	message := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
	signature := ed25519.Sign(s.private, []byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
