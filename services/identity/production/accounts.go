// Package production owns a separate account/session authority for the future
// production IdP. This file is an internal Mongo primitive, not a login HTTP API.
package production

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	accountCollectionName = "native_accounts"
	accountSource         = "shadowops-production-native"
	sessionHandlePrefix   = "so1_"
)

var (
	ErrAccountDenied = errors.New("production Identity account or credentials denied")
	ErrAccountStore  = errors.New("production Identity account storage unavailable")
	accountAlias     = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)
)

// AccountAuthority never accepts staging account aliases, legacy migrations,
// product roles or foreign issuers. It also never opens a public HTTP listener.
type AccountAuthority struct {
	client   *mongo.Client
	accounts *mongo.Collection
	sessions *Store
	guard    *session.VersionedValidator
}

type nativeAccount struct {
	Subject           string `bson:"_id"`
	CredentialHash    string `bson:"credential_hash"`
	CredentialVersion int64  `bson:"credential_version"`
	SessionVersion    int64  `bson:"session_version"`
}

// NewAccountAuthority creates only production indexes on the dedicated DB.
// The caller MUST first verify that the Mongo principal, TLS and CA are
// independent from staging; the driver handle alone cannot prove that.
func NewAccountAuthority(ctx context.Context, client *mongo.Client) (*AccountAuthority, error) {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return nil, ErrAccountDenied
	}
	db := client.Database(Database)
	sessions, err := NewSessionStore(ctx, db)
	if err != nil {
		return nil, ErrAccountStore
	}
	accounts := db.Collection(accountCollectionName, options.Collection().
		SetReadConcern(readconcern.Majority()).
		SetReadPreference(readpref.Primary()).
		SetWriteConcern(writeconcern.Majority()))
	_, err = accounts.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "environment", Value: 1}, {Key: "source", Value: 1}, {Key: "alias_key", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("production_native_alias_unique"),
	})
	if err != nil {
		return nil, ErrAccountStore
	}
	authority := &AccountAuthority{client: client, accounts: accounts, sessions: sessions}
	authority.guard, err = session.NewVersionedValidator("production", sessions, authority)
	if err != nil {
		return nil, ErrAccountStore
	}
	return authority, nil
}

func (a *AccountAuthority) ready(ctx context.Context) bool {
	return a != nil && a.client != nil && a.accounts != nil && a.sessions != nil &&
		a.guard != nil && ctx != nil && ctx.Err() == nil
}

func validPassword(input string) bool {
	return len(input) > 0 && len(input) <= 4096 &&
		utf8.ValidString(input) && utf8.RuneCountInString(input) >= 15
}

func generateSubject() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrAccountStore
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}

// Register creates an entirely new, production-native account. No browser
// endpoint calls this yet. Existing staging accounts are not imported.
func (a *AccountAuthority) Register(ctx context.Context, alias, candidate string) (string, error) {
	if !a.ready(ctx) || !accountAlias.MatchString(alias) || !validPassword(candidate) {
		return "", ErrAccountDenied
	}
	encoded, err := password.HashNew(candidate)
	if err != nil {
		return "", ErrAccountDenied
	}
	subject, err := generateSubject()
	if err != nil {
		return "", err
	}
	_, err = a.accounts.InsertOne(ctx, bson.D{
		{Key: "_id", Value: subject},
		{Key: "environment", Value: "production"},
		{Key: "source", Value: accountSource},
		{Key: "alias_key", Value: alias},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
		{Key: "credential_hash", Value: encoded},
		{Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)},
		{Key: "login_fence", Value: int64(0)},
		{Key: "created_at", Value: time.Now().UTC()},
	})
	if mongo.IsDuplicateKeyError(err) {
		return "", ErrAccountDenied
	}
	if err != nil {
		return "", ErrAccountStore
	}
	return subject, nil
}

func activeAccountFilter() bson.D {
	return bson.D{
		{Key: "environment", Value: "production"},
		{Key: "source", Value: accountSource},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
	}
}

// Issue authenticates against an isolated active account and atomically
// binds the session insert to an account write fence. Concurrent suspension
// or password mutation conflicts with the transaction, never authorizing a
// session using stale credentials. The opaque handle is returned only after
// Mongo majority-commits both writes.
func (a *AccountAuthority) Issue(ctx context.Context, alias, candidate string) (string, error) {
	if !a.ready(ctx) || !accountAlias.MatchString(alias) ||
		len(candidate) == 0 || len(candidate) > 4096 {
		return "", ErrAccountDenied
	}
	filter := append(activeAccountFilter(), bson.E{Key: "alias_key", Value: alias})
	var current nativeAccount
	if err := a.accounts.FindOne(ctx, filter).Decode(&current); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrAccountDenied
		}
		return "", ErrAccountStore
	}
	if !sessionSubjectPattern.MatchString(current.Subject) ||
		current.CredentialVersion < 1 || current.SessionVersion < 1 ||
		current.CredentialVersion == math.MaxInt64 ||
		current.SessionVersion == math.MaxInt64 ||
		!password.Verify(candidate, current.CredentialHash) {
		return "", ErrAccountDenied
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", ErrAccountStore
	}
	handle := sessionHandlePrefix + base64.RawURLEncoding.EncodeToString(random[:])
	rawKey := append([]byte("shadowops-session-v1:production:"), random[:]...)
	digest := sha256.Sum256(rawKey)
	now := time.Now().UTC()
	rec := session.Record{
		Digest: digest, Environment: "production", Subject: current.Subject,
		IssuedAt: now, ExpiresAt: now.Add(session.Lifetime),
		SessionVersion: current.SessionVersion,
	}
	txnSession, err := a.client.StartSession()
	if err != nil {
		return "", ErrAccountStore
	}
	defer txnSession.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = txnSession.WithTransaction(ctx, func(tx context.Context) (any, error) {
		cas := append(append(bson.D{}, filter...),
			bson.E{Key: "_id", Value: current.Subject},
			bson.E{Key: "credential_hash", Value: current.CredentialHash},
			bson.E{Key: "credential_version", Value: current.CredentialVersion},
			bson.E{Key: "session_version", Value: current.SessionVersion},
		)
		result, err := a.accounts.UpdateOne(tx, cas,
			bson.D{{Key: "$inc", Value: bson.D{{Key: "login_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrAccountDenied
		}
		if err := a.sessions.Create(tx, rec); err != nil {
			return nil, err
		}
		return nil, nil
	}, txn)
	if err != nil {
		if errors.Is(err, ErrAccountDenied) {
			return "", ErrAccountDenied
		}
		return "", ErrAccountStore
	}
	return handle, nil
}

// CurrentSessionVersion is read from the authoritative production account
// document, never from claims or a cached identity. It intentionally returns
// false for suspended, missing or disabled identities.
func (a *AccountAuthority) CurrentSessionVersion(ctx context.Context, environment, subject string) (int64, bool, error) {
	if !a.ready(ctx) || environment != "production" || !sessionSubjectPattern.MatchString(subject) {
		return 0, false, ErrAccountDenied
	}
	filter := append(activeAccountFilter(), bson.E{Key: "_id", Value: subject})
	var record nativeAccount
	err := a.accounts.FindOne(ctx, filter).Decode(&record)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, ErrAccountStore
	}
	if record.SessionVersion < 1 || record.CredentialVersion < 1 {
		return 0, false, nil
	}
	return record.SessionVersion, true, nil
}

// Validate is a point-in-time read-only observation, NOT an authorization
// lease. Later application token freshness must check this state on every
// protected operation and bind JTI to authoritative token persistence.
func (a *AccountAuthority) Validate(ctx context.Context, handle string) (string, error) {
	if !a.ready(ctx) {
		return "", ErrAccountDenied
	}
	return a.guard.Validate(ctx, handle)
}

// SuspendAndRevoke transactionally disables the account, bumps its version,
// and deletes every session. The same account-document write fence used by
// Issue makes concurrent login vs suspension conflict on Mongo primary.
func (a *AccountAuthority) SuspendAndRevoke(ctx context.Context, subject string) error {
	if !a.ready(ctx) || !sessionSubjectPattern.MatchString(subject) {
		return ErrAccountDenied
	}
	filter := append(activeAccountFilter(), bson.E{Key: "_id", Value: subject})
	var current nativeAccount
	if err := a.accounts.FindOne(ctx, filter).Decode(&current); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrAccountDenied
		}
		return ErrAccountStore
	}
	if current.SessionVersion < 1 || current.SessionVersion == math.MaxInt64 {
		return ErrAccountDenied
	}
	s, err := a.client.StartSession()
	if err != nil {
		return ErrAccountStore
	}
	defer s.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = s.WithTransaction(ctx, func(tx context.Context) (any, error) {
		cas := append(append(bson.D{}, filter...),
			bson.E{Key: "session_version", Value: current.SessionVersion},
		)
		updated, err := a.accounts.UpdateOne(tx, cas, bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "state", Value: "suspended"},
				{Key: "credentials_disabled", Value: true},
			}},
			{Key: "$inc", Value: bson.D{{Key: "session_version", Value: int64(1)}}},
		})
		if err != nil {
			return nil, err
		}
		if updated.ModifiedCount != 1 {
			return nil, ErrAccountDenied
		}
		return nil, a.sessions.DeleteSubject(tx, "production", subject)
	}, txn)
	if err != nil {
		if errors.Is(err, ErrAccountDenied) {
			return ErrAccountDenied
		}
		return ErrAccountStore
	}
	return nil
}
