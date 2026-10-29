// Package mongostore implements the Identity session.Store against a dedicated
// staging Mongo database. No production driver, credentials or HTTP integration.
package mongostore

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
	StagingDatabase = "shadowops_identity_staging"
	collectionName  = "sessions"
)

var ErrInvalidStore = errors.New("identity staging session store requires isolated Mongo database")

type Store struct{ collection *mongo.Collection }

var _ session.Store = (*Store)(nil)

type document struct {
	Digest      string    `bson:"digest"`
	Environment string    `bson:"environment"`
	Subject     string    `bson:"subject"`
	IssuedAt    time.Time `bson:"issued_at"`
	ExpiresAt   time.Time `bson:"expires_at"`
}

func validRecord(r session.Record) bool {
	return r.Environment == "staging" && r.Subject != "" &&
		r.Digest != ([32]byte{}) && !r.IssuedAt.IsZero() && !r.ExpiresAt.IsZero() &&
		r.ExpiresAt.After(r.IssuedAt) && r.ExpiresAt.Sub(r.IssuedAt) <= session.Lifetime
}

// New creates required unique/TTL indexes before returning a usable Store.
// The supplied connection must be to a dedicated isolated staging database;
// never bind the future production service to this implementation. The caller
// owns client credentials, TLS and lifecycle.
func New(ctx context.Context, db *mongo.Database) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || db.Name() != StagingDatabase {
		return nil, ErrInvalidStore
	}
	col := db.Collection(collectionName,
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
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || !validRecord(r) {
		return ErrInvalidStore
	}
	_, err := s.collection.InsertOne(ctx, document{
		Digest: hex.EncodeToString(r.Digest[:]), Environment: r.Environment,
		Subject: r.Subject, IssuedAt: r.IssuedAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(),
	})
	return err
}

func (s *Store) Get(ctx context.Context, environment string, digest [32]byte) (session.Record, bool, error) {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "staging" || digest == ([32]byte{}) {
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
	if doc.Environment != environment || doc.Digest != hex.EncodeToString(digest[:]) {
		return session.Record{}, false, ErrInvalidStore
	}
	return session.Record{
		Digest: digest, Environment: environment, Subject: doc.Subject,
		IssuedAt: doc.IssuedAt.UTC(), ExpiresAt: doc.ExpiresAt.UTC(),
	}, true, nil
}

// Swap performs one in-place compare-and-swap. Mongo's single-document
// conditional UpdateOne is atomic even with concurrent application replicas.
// It changes the indexed digest but never creates a new row or changes expiry,
// subject or environment; a concurrent revoke cannot resurrect a session.
func (s *Store) Swap(ctx context.Context, environment string, old [32]byte, next session.Record, now time.Time) (bool, error) {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil ||
		environment != "staging" || old == next.Digest || old == ([32]byte{}) ||
		now.IsZero() || !validRecord(next) || next.Environment != environment ||
		next.IssuedAt.After(now.Add(30 * time.Second)) || !next.IssuedAt.After(now.Add(-time.Second)) ||
		!now.Before(next.ExpiresAt) {
		return false, ErrInvalidStore
	}
	filter := bson.D{
		{Key: "environment", Value: environment},
		{Key: "digest", Value: hex.EncodeToString(old[:])},
		{Key: "subject", Value: next.Subject},
		{Key: "expires_at", Value: bson.D{{Key: "$eq", Value: next.ExpiresAt.UTC()}, {Key: "$gt", Value: now.UTC()}}},
		{Key: "issued_at", Value: bson.D{{Key: "$lte", Value: now.Add(30*time.Second).UTC()}}},
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
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "staging" || digest == ([32]byte{}) {
		return ErrInvalidStore
	}
	_, err := s.collection.DeleteOne(ctx, bson.D{
		{Key: "environment", Value: environment},
		{Key: "digest", Value: hex.EncodeToString(digest[:])},
	})
	return err
}
func (s *Store) DeleteSubject(ctx context.Context, environment, subject string) error {
	if s == nil || s.collection == nil || ctx == nil || ctx.Err() != nil || environment != "staging" || subject == "" {
		return ErrInvalidStore
	}
	_, err := s.collection.DeleteMany(ctx, bson.D{
		{Key: "environment", Value: environment}, {Key: "subject", Value: subject},
	})
	return err
}
