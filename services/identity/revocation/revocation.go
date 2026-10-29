// Package revocation holds a staging-only, offline suspension primitive.
// It does not authenticate requesters, change passwords or expose HTTP routes.
package revocation

import (
	"context"
	"errors"
	"math"
	"regexp"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const StagingDatabase = "shadowops_identity_staging"

var (
	ErrInvalid     = errors.New("invalid staging identity revocation request")
	ErrConflict    = errors.New("staging identity account no longer matches expected version")
	subjectPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// Revoker is an offline, staging-only administrative operation. Its caller
// must independently authorize the action; no user-facing path is wired.
// All collections and the logical session must use one Mongo client.
type Revoker struct {
	client   *mongo.Client
	accounts *mongo.Collection
	sessions *mongo.Collection
	// Internal failure hook for proving rollback in integration tests.
	// Nil in every production instance.
	afterAccountWrite func() error
}

func NewStagingRevoker(client *mongo.Client) (*Revoker, error) {
	if client == nil {
		return nil, ErrInvalid
	}
	db := client.Database(StagingDatabase)
	return &Revoker{client: client, accounts: db.Collection("pending_accounts"), sessions: db.Collection("sessions")}, nil
}

// SuspendAndRevoke atomically (1) disables a previously active account,
// (2) increments its session version and (3) deletes all its session rows.
// A failed delete or interrupted commit rolls back the account update too.
// Transactions require a Mongo replica set (standalone mongod is insufficient).
// Calling this twice with the same expected version is a conflict, not a
// second version bump; concurrent calls never report multiple successes.
// The account state remains credential-staged-disabled: NO login is enabled.
func (r *Revoker) SuspendAndRevoke(ctx context.Context, subject string, expectedVersion int64) error {
	if r == nil || r.client == nil || r.accounts == nil || r.sessions == nil || ctx == nil || ctx.Err() != nil ||
		!subjectPattern.MatchString(subject) || expectedVersion < 1 || expectedVersion == math.MaxInt64 {
		return ErrInvalid
	}
	sess, err := r.client.StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(context.Background())

	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		filter := bson.D{
			{Key: "_id", Value: subject},
			{Key: "environment", Value: "staging"},
			{Key: "state", Value: "active"},
			{Key: "credentials_disabled", Value: false},
			{Key: "session_version", Value: expectedVersion},
		}
		change := bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "state", Value: "credential-staged-disabled"},
				{Key: "credentials_disabled", Value: true},
			}},
			{Key: "$inc", Value: bson.D{{Key: "session_version", Value: int64(1)}}},
		}
		result, err := r.accounts.UpdateOne(tx, filter, change)
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrConflict
		}
		if r.afterAccountWrite != nil {
			if err := r.afterAccountWrite(); err != nil {
				return nil, err
			}
		}
		_, err = r.sessions.DeleteMany(tx, bson.D{
			{Key: "environment", Value: "staging"},
			{Key: "subject", Value: subject},
		})
		if err != nil {
			return nil, err
		}
		return nil, nil
	}, txn)
	return err
}
