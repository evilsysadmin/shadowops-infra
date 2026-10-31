package roles

import (
	"context"
	"reflect"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// PrepareStagingRoleJournalIndex is an OFFLINE, DDL-only schema-owner action.
// It must be run using a dedicated schema-maintainer Mongo principal BEFORE
// an operator-only role executor is allowed to start. It never issues a
// role grant, repairs existing unsafe indexes, or creates signing policies.
// MongoDB may implicitly create the exact journal collection when its first
// authorized index is created; the schema owner never gets collection-wide DDL.
func PrepareStagingRoleJournalIndex(ctx context.Context, client *mongo.Client) error {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return ErrRoleStore
	}
	journal := client.Database(roleDatabase).Collection(roleJournal)
	cursor, err := journal.Indexes().List(ctx)
	if err != nil {
		// Insufficient listIndexes permissions or a failed preflight must
		// never be bypassed by attempting CreateOne.
		return ErrRoleStore
	}
	var indexes []struct {
		Name    string   `bson:"name"`
		Key     bson.D   `bson:"key"`
		Unique  bool     `bson:"unique"`
		Sparse  bool     `bson:"sparse"`
		Partial bson.Raw `bson:"partialFilterExpression"`
		TTL     *int64   `bson:"expireAfterSeconds"`
	}
	if err := cursor.All(ctx, &indexes); err != nil {
		return ErrRoleStore
	}
	found := false
	for _, index := range indexes {
		// An unrelated TTL index can still erase historical role approvals.
		// Never add an index while such a retention hazard exists.
		if index.TTL != nil {
			return ErrRoleStore
		}
		if index.Name == roleJournalIndex {
			if !index.Unique || index.Sparse || len(index.Partial) != 0 ||
				!reflect.DeepEqual(index.Key, roleJournalKeys()) {
				return ErrRoleStore
			}
			found = true
		}
	}
	if !found {
		_, err := journal.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    roleJournalKeys(),
			Options: options.Index().SetName(roleJournalIndex).SetUnique(true),
		})
		if err != nil {
			return ErrRoleStore
		}
	}
	// Verify after DDL (or when already present), not merely a CreateOne OK.
	return verifyRoleJournal(ctx, journal)
}
