package revocation

import (
	"context"
	"errors"
	"reflect"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrAuditIndexNotReady means the durable, unique, non-TTL journal contract
// has not been independently provisioned. A normal runtime never repairs it.
var ErrAuditIndexNotReady = errors.New("staging identity administrative audit indexes not ready")

type journalIndexSpec struct {
	collection string
	name       string
}

var administrativeJournals = [...]journalIndexSpec{
	{collection: suspensionJournalCollection, name: "staging_action_nonce_unique"},
	{collection: retirementJournalCollection, name: "policy_retirement_nonce_unique"},
}

func requiredJournalKeys() bson.D {
	return bson.D{
		{Key: "environment", Value: int32(1)},
		{Key: "action", Value: int32(1)},
		{Key: "nonce", Value: int32(1)},
	}
}

// PrepareStagingAdministrativeIndexes is a DDL-only, OFFLINE maintenance
// operation. Run it with a separate schema owner before creating any
// runtime revocation/bootstrap/recovery primitive, then revoke those DDL
// privileges. Do NOT call it with live operator or login credentials.
func PrepareStagingAdministrativeIndexes(ctx context.Context, client *mongo.Client) error {
	if ctx == nil || ctx.Err() != nil || client == nil {
		return ErrAuditIndexNotReady
	}
	db := client.Database(StagingDatabase)
	for _, spec := range administrativeJournals {
		_, err := db.Collection(spec.collection).Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys: requiredJournalKeys(),
			Options: options.Index().SetName(spec.name).SetUnique(true),
		})
		if err != nil {
			return ErrAuditIndexNotReady
		}
	}
	for _, spec := range administrativeJournals {
		if err := verifyStagingJournalIndex(ctx, db.Collection(spec.collection), spec.name); err != nil {
			return err
		}
	}
	return nil
}

// verifyStagingJournalIndex is READ-ONLY. It checks the exact expected
// compound key, uniqueness, and absence of TTL, sparse or partial filters.
// Any TTL index on a journal can destroy permanent replay evidence, even if
// the required unique index itself does not have TTL.
func verifyStagingJournalIndex(ctx context.Context, journal *mongo.Collection, requiredName string) error {
	if ctx == nil || ctx.Err() != nil || journal == nil {
		return ErrAuditIndexNotReady
	}
	cursor, err := journal.Indexes().List(ctx)
	if err != nil {
		return ErrAuditIndexNotReady
	}
	var entries []struct {
		Name               string   `bson:"name"`
		Key                bson.D   `bson:"key"`
		Unique             bool     `bson:"unique"`
		Sparse             bool     `bson:"sparse"`
		PartialFilter      bson.Raw `bson:"partialFilterExpression"`
		ExpireAfterSeconds *int64   `bson:"expireAfterSeconds"`
	}
	if err := cursor.All(ctx, &entries); err != nil {
		return ErrAuditIndexNotReady
	}
	found := false
	for _, index := range entries {
		if index.ExpireAfterSeconds != nil {
			return ErrAuditIndexNotReady
		}
		if index.Name == requiredName {
			if !index.Unique || index.Sparse || len(index.PartialFilter) != 0 ||
				!reflect.DeepEqual(index.Key, requiredJournalKeys()) {
				return ErrAuditIndexNotReady
			}
			found = true
		}
	}
	if !found {
		return ErrAuditIndexNotReady
	}
	return nil
}
