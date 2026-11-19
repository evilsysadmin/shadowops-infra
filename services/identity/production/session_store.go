// Package production binds versioned Identity sessions to the exact isolated
// production Mongo database; it never accepts legacy unversioned records.
// No browser or token issuance is activated by this driver.
package production

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const sessionCollectionName = "sessions"

var (
	ErrInvalidStore = errors.New("identity production session store requires isolated Mongo database")
	sessionSubjectPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}// Package mongostore implements the Identity session.Store against a dedicated
// production Mongo database. No production driver, credentials or HTTP integration.
package production

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const sessionCollectionName = "sessions"

)
)

type Store struct{ collection *mongo.Collection }

// OpenExistingSessionStore binds to the already provisioned session collection
// without creating indexes or requiring schema privileges. The caller must
// independently verify the database identity and its principal's privileges.
func OpenExistingSessionStore(db *mongo.Database) (*Store, error) {
	if db == nil || db.Name() != Database {
		return nil, ErrInvalidStore
	}
	return &Store{collection: db.Collection(sessionCollectionName, options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))}, nil
}

var _ session.Store = (*Store)(nil)

type document struct {
	Digest         string    `bson:"digest"`
	Environment    string    `bson:"environment"`
	Subject        string    `bson:"subject"`
	IssuedAt       time.Time `bson:"issued_at"`
	ExpiresAt      time.Time `bson:"expires_at"`
	SessionVersion int64     `bson:"session_version"`
}

func validProductionRecord(r session.Record) bool {
	return r.Environment == "production" && sessionSubjectPattern.MatchString(r.Subject) &&
		r.Digest != ([32]byte{}) && !r.IssuedAt.IsZero() && !r.ExpiresAt.IsZero() &&
		r.ExpiresAt.After(r.IssuedAt) && r.ExpiresAt.Sub(r.IssuedAt) <= session.Lifetime && r.SessionVersion > 0
}

// New creates required unique/TTL indexes before returning a usable Store.
// The supplied connection must be to the exact isolated production database;
// never use credentials for the staging or product databases. The caller
// owns client credentials, TLS and lifecycle.
func NewSessionStore(ctx context.Context, db *mongo.Database) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || db.Name() != Database {
		return nil, ErrInvalidStore
	}
	col := db.Collection(sessionCollectionName,
		options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	models := []mongo.IndexModel{
		{Keys: bson.D{{Key: "environment", Value: 1}, {Key: "digest", Value: 1}},
			Options: options.Index().SetName("environment_digest_unique").SetUnique(true)},
		{Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("expires_at_ttl").SetExpireAfterSeconds(0)},
		{Keys: bson.D{{Key: "environment", Value: 1}, {Key: "subject", Value: 1}},
			Options: options.Index().SetName("environment_subject_revoke")},
	}
	if _, err := col.Indexes().CreateMany(ctx, models); err != nil {
		return nil, err
	}
	return &Store{collection: col}, nil
}

func (s *Store) Create(ctx context.Context, r session.Record) error {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || !validProductionRecord(r) {
		return ErrInvalidStore
	}
	_, err := s.collection.InsertOne(ctx, document{
		Digest: hex.EncodeToString(r.Digest[:]), Environment: r.Environment,
		Subject: r.Subject, IssuedAt: r.IssuedAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(), SessionVersion: r.SessionVersion,
	})
	return err
}

func (s *Store) Get(ctx context.Context, environment string, digest [32]byte) (session.Record, bool, error) {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "production" || digest == ([32]byte{}) {
		return session.Record{}, false, ErrInvalidStore
	}
	var doc document
	err := s.collection.FindOne(ctx, bson.D{
		{Key: "environment", Value: environment},
		{Key: "digest", Value: hex.EncodeToString(digest[:])},
	}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return session.Record{}, false, nil
	}
	if err != nil {
		return session.Record{}, false, err
	}
	if doc.Environment != environment || doc.Digest != hex.EncodeToString(digest[:]) || !validProductionRecord(session.Record{
		Digest: digest, Environment: doc.Environment, Subject: doc.Subject,
		IssuedAt: doc.IssuedAt, ExpiresAt: doc.ExpiresAt, SessionVersion: doc.SessionVersion,
	}) {
		return session.Record{}, false, ErrInvalidStore
	}
	return session.Record{
		Digest: digest, Environment: environment, Subject: doc.Subject,
		IssuedAt: doc.IssuedAt.UTC(), ExpiresAt: doc.ExpiresAt.UTC(), SessionVersion: doc.SessionVersion,
	}, true, nil
}

// Swap performs one in-place compare-and-swap. Mongo's single-document
// conditional UpdateOne is atomic even with concurrent application replicas.
// It changes the indexed digest but never creates a new row or changes expiry,
// subject or environment; a concurrent revoke cannot resurrect a session.
func (s *Store) Swap(ctx context.Context, environment string, old [32]byte, next session.Record, now time.Time) (bool, error) {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil ||
		environment != "production" || old == next.Digest || old == ([32]byte{}) ||
		now.IsZero() || !validProductionRecord(next) || next.Environment != environment ||
		next.IssuedAt.After(now.Add(30*time.Second)) || !next.IssuedAt.After(now.Add(-time.Second)) ||
		!now.Before(next.ExpiresAt) {
		return false, ErrInvalidStore
	}
	filter := bson.D{
		{Key: "environment", Value: environment},
		{Key: "digest", Value: hex.EncodeToString(old[:])},
		{Key: "subject", Value: next.Subject},
		{Key: "session_version", Value: next.SessionVersion},
		{Key: "expires_at", Value: bson.D{{Key: "$eq", Value: next.ExpiresAt.UTC()}, {Key: "$gt", Value: now.UTC()}}},
		{Key: "issued_at", Value: bson.D{{Key: "$lte", Value: now.Add(30 * time.Second).UTC()}}},
	}
	change := bson.D{{Key: "$set", Value: bson.D{
		{Key: "digest", Value: hex.EncodeToString(next.Digest[:])},
		{Key: "issued_at", Value: next.IssuedAt.UTC()},
	}}}
	result, err := s.collection.UpdateOne(ctx, filter, change)
	if err != nil {
		return false, err
	}
	return result.ModifiedCount == 1, nil
}

func (s *Store) Delete(ctx context.Context, environment string, digest [32]byte) error {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "production" || digest == ([32]byte{}) {
		return ErrInvalidStore
	}
	_, err := s.collection.DeleteOne(ctx, bson.D{
		{Key: "environment", Value: environment},
		{Key: "digest", Value: hex.EncodeToString(digest[:])},
	})
	return err
}
func (s *Store) DeleteSubject(ctx context.Context, environment, subject string) error {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "production" || subject == "" {
		return ErrInvalidStore
	}
	_, err := s.collection.DeleteMany(ctx, bson.D{
		{Key: "environment", Value: environment}, {Key: "subject", Value: subject},
	})
	return err
}
