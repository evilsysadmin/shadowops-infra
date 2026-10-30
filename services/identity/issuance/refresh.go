package issuance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

const stagingHandlePrefix = "so1_"

// stagingHandleDigest implements exactly the domain-separated opaque session
// handle format used by session.Manager. Decoding rejects noncanonical base64.
func stagingHandleDigest(handle string) ([32]byte, bool) {
	if len(handle) != len(stagingHandlePrefix)+43 || handle[:len(stagingHandlePrefix)] != stagingHandlePrefix {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(handle[len(stagingHandlePrefix):])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != handle[len(stagingHandlePrefix):] {
		return [32]byte{}, false
	}
	input := append([]byte("shadowops-session-v1:staging:"), raw...)
	return sha256.Sum256(input), true
}

func newStagingHandle() (string, [32]byte, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", [32]byte{}, ErrStore
	}
	handle := stagingHandlePrefix + base64.RawURLEncoding.EncodeToString(secret[:])
	digest, valid := stagingHandleDigest(handle)
	if !valid {
		return "", [32]byte{}, ErrStore
	}
	return handle, digest, nil
}

// Refresh rotates an existing version-bound staging handle exactly once.
// HTTP cookies and CSRF/rate limits belong to the separate transport; this
// primitive assigns no privileges. Account eligibility and session version are
// checked by a transactional write to the same account document modified by
// SuspendAndRevoke. Session CAS and the account fence commit together, so
// a refresh racing suspension cannot resurrect a session after revocation.
// No refresh may extend the existing absolute expiry.
func (i *Issuer) Refresh(ctx context.Context, oldHandle string) (string, error) {
	if i == nil || i.client == nil || i.accounts == nil || i.sessions == nil ||
		ctx == nil || ctx.Err() != nil {
		return "", ErrDenied
	}
	oldDigest, valid := stagingHandleDigest(oldHandle)
	if !valid {
		return "", ErrDenied
	}
	old, exists, err := i.sessions.Get(ctx, "staging", oldDigest)
	if err != nil {
		return "", ErrStore
	}
	now := time.Now().UTC()
	if !exists || old.Digest != oldDigest || old.Environment != "staging" ||
		!uuidV4.MatchString(old.Subject) || old.SessionVersion <= 0 ||
		!old.IssuedAt.Before(old.ExpiresAt) || old.IssuedAt.After(now.Add(30*time.Second)) ||
		old.ExpiresAt.Sub(old.IssuedAt) > session.Lifetime || !now.Before(old.ExpiresAt) {
		return "", ErrDenied
	}
	nextHandle, nextDigest, err := newStagingHandle()
	if err != nil {
		return "", ErrStore
	}
	next := session.Record{
		Digest: nextDigest, Environment: "staging", Subject: old.Subject,
		IssuedAt: now, ExpiresAt: old.ExpiresAt, SessionVersion: old.SessionVersion,
	}
	sess, err := i.client.StartSession()
	if err != nil {
		return "", ErrStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		filter := bson.D{
			{Key: "_id", Value: old.Subject},
			{Key: "environment", Value: "staging"},
			{Key: "state", Value: "active"},
			{Key: "credentials_disabled", Value: false},
			{Key: "session_version", Value: old.SessionVersion},
		}
		// Updating the account is essential: a read-only check would race a
		// concurrent suspension's delete across the two collections.
		result, err := i.accounts.UpdateOne(tx, filter,
			bson.D{{Key: "$inc", Value: bson.D{{Key: "login_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrDenied
		}
		if i.afterFence != nil {
			if err := i.afterFence(); err != nil {
				return nil, err
			}
		}
		swapped, err := i.sessions.Swap(tx, "staging", oldDigest, next, now)
		if err != nil {
			return nil, err
		}
		if !swapped {
			return nil, ErrDenied
		}
		return nil, nil
	}, txn)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	// WithTransaction has confirmed majority commit before the raw handle
	// crosses this boundary. An uncertain commit fails closed above.
	return nextHandle, nil
}
