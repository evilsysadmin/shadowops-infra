// Package issuance provides an offline-only, staging-bound credential check
// and atomic Mongo session issuance. No login HTTP endpoint uses this package.
package issuance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/mongostore"
	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const stagingDatabase = "shadowops_identity_staging"

var (
	ErrDenied = errors.New("identity credential issuance denied")
	ErrStore  = errors.New("identity credential issuance unavailable")
	uuidV4    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type Issuer struct {
	client       *mongo.Client
	accounts     *mongo.Collection
	sessions     session.Store
	afterFence   func() error // tests only: force transaction rollback
}

// NewStagingIssuer initializes the session indexes *before* any transaction.
// Only the dedicated staging database is supported. No handler or service
// instantiates this issuer in production; caller must provide its own client.
func NewStagingIssuer(ctx context.Context, client *mongo.Client) (*Issuer, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrDenied
	}
	db := client.Database(stagingDatabase)
	store, err := mongostore.New(ctx, db)
	if err != nil {
		return nil, ErrStore
	}
	accounts := db.Collection("pending_accounts", options.Collection().
		SetReadConcern(readconcern.Majority()).SetReadPreference(readpref.Primary()))
	return &Issuer{client: client, accounts: accounts, sessions: store}, nil
}

type account struct {
	CredentialHash    string `bson:"credential_hash"`
	CredentialVersion int64  `bson:"credential_version"`
	SessionVersion    int64  `bson:"session_version"`
}

// Issue authenticates against the *existing* staged credential for a test-only
// active account. Password KDF is outside the transaction; the transaction
// compares the same hash + both versions and writes the account document to
// conflict with a simultaneous SuspendAndRevoke transaction. The raw handle
// is returned ONLY after a majority-committed account fence + session insert.
//
// WARNING: no HTTP/login/rate-limit/claimant enrollment is wired to this;
// the only active accounts currently available are synthetic CI fixtures.
func (i *Issuer) Issue(ctx context.Context, subject, candidate string) (string, error) {
	if i == nil || i.client == nil || i.accounts == nil || i.sessions == nil ||
		ctx == nil || ctx.Err() != nil || !uuidV4.MatchString(subject) ||
		len(candidate) == 0 || len(candidate) > 4096 {
		return "", ErrDenied
	}
	filter := bson.D{
		{Key: "_id", Value: subject},
		{Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
	}
	var current account
	if err := i.accounts.FindOne(ctx, filter).Decode(&current); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	if current.SessionVersion < 1 || current.CredentialVersion < 1 ||
		!password.Verify(candidate, current.CredentialHash) {
		return "", ErrDenied
	}

	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", ErrStore
	}
	handle := "so1_" + base64.RawURLEncoding.EncodeToString(random[:])
	key := append([]byte("shadowops-session-v1:staging:"), random[:]...)
	digest := sha256.Sum256(key)
	now := time.Now().UTC()
	newSession := session.Record{
		Digest: digest, Environment: "staging", Subject: subject,
		IssuedAt: now, ExpiresAt: now.Add(session.Lifetime),
		SessionVersion: current.SessionVersion,
	}

	sess, err := i.client.StartSession()
	if err != nil {
		return "", ErrStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		cas := append(bson.D{}, filter...)
		cas = append(cas,
			bson.E{Key: "credential_hash", Value: current.CredentialHash},
			bson.E{Key: "credential_version", Value: current.CredentialVersion},
			bson.E{Key: "session_version", Value: current.SessionVersion},
		)
		// A real write on the SAME document as the revocation bump creates
		// a Mongo transaction write conflict rather than a racy read-only
		// account snapshot followed by an unprotected session insert.
		result, err := i.accounts.UpdateOne(tx, cas,
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
		if err := i.sessions.Create(tx, newSession); err != nil {
			return nil, err
		}
		return nil, nil
	}, txn)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	return handle, nil
}
