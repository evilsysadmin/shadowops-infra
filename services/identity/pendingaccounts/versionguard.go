package pendingaccounts

import (
	"context"
	"errors"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// VersionGuard is read-only and staging-only. No real account can become
// active through the existing pending account API.
type VersionGuard struct {
	accounts *mongo.Collection
}

var _ session.AccountVersionReader = (*VersionGuard)(nil)

func NewVersionGuard(db *mongo.Database) (*VersionGuard, error) {
	if db == nil || db.Name() != StagingDatabase {
		return nil, ErrInvalid
	}
	col := db.Collection(collectionName, options.Collection().
		SetReadConcern(readconcern.Majority()).SetReadPreference(readpref.Primary()))
	return &VersionGuard{accounts: col}, nil
}

// CurrentSessionVersion reads from Mongo on EVERY call, rejecting disabled,
// pending, reviewed, unversioned and missing accounts. No local version cache.
func (g *VersionGuard) CurrentSessionVersion(ctx context.Context, environment, subject string) (int64, bool, error) {
	if g == nil || g.accounts == nil || ctx == nil || ctx.Err() != nil ||
		environment != "staging" || !subjectRe.MatchString(subject) {
		return 0, false, ErrInvalid
	}
	filter := bson.D{
		{Key: "_id", Value: subject},
		{Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"},
		{Key: "credentials_disabled", Value: false},
	}
	opts := options.FindOne().SetProjection(bson.D{{Key: "session_version", Value: 1}})
	var doc struct {
		SessionVersion int64 `bson:"session_version"`
	}
	err := g.accounts.FindOne(ctx, filter, opts).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if doc.SessionVersion <= 0 {
		return 0, false, nil
	}
	return doc.SessionVersion, true, nil
}
