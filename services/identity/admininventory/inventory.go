// Package admininventory provides a read-only staging account inventory.
// It does not authenticate administrators and must not be exposed as a route
// until a trusted caller has independently authorized the requesting operator.
package admininventory

import (
	"context"
	"errors"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var ErrInvalid = errors.New("invalid staging inventory request")
var subjectPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Account contains only administrative display fields; no authentication
// material or session handles are selected from MongoDB.
type Account struct {
	Subject             string    `json:"subject" bson:"_id"`
	Name                string    `json:"name" bson:"alias_key"`
	State               string    `json:"state" bson:"state"`
	CredentialsDisabled bool      `json:"credentialsDisabled" bson:"credentials_disabled"`
	CreatedAt           time.Time `json:"createdAt" bson:"created_at"`
}

type Page struct {
	Accounts []Account `json:"accounts"`
	Next     string    `json:"next,omitempty"`
}

type Inventory struct{ accounts *mongo.Collection }

// NewStaging accepts only the fixed staging database. Its Mongo principal must
// have find-only access to pending_accounts and must be provisioned separately
// from the public Identity runtime.
func NewStaging(db *mongo.Database) (*Inventory, error) {
	if db == nil || db.Name() != "shadowops_identity_staging" {
		return nil, ErrInvalid
	}
	return &Inventory{accounts: db.Collection("pending_accounts")}, nil
}

// List returns at most 50 native accounts in stable subject order. The cursor
// is the last returned UUID; no name or secret is embedded in it. Legacy
// reservations are intentionally excluded and accounts are never matched by name.
func (i *Inventory) List(ctx context.Context, after string, limit int) (Page, error) {
	if i == nil || i.accounts == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > 50 || (after != "" && !subjectPattern.MatchString(after)) {
		return Page{}, ErrInvalid
	}
	filter := bson.D{{Key: "environment", Value: "staging"}, {Key: "source", Value: "shadowops-identity"}}
	if after != "" {
		filter = append(filter, bson.E{Key: "_id", Value: bson.D{{Key: "$gt", Value: after}}})
	}
	opts := options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}, {Key: "alias_key", Value: 1}, {Key: "state", Value: 1}, {Key: "credentials_disabled", Value: 1}, {Key: "created_at", Value: 1}}).SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(int64(limit + 1))
	cursor, err := i.accounts.Find(ctx, filter, opts)
	if err != nil {
		return Page{}, err
	}
	defer cursor.Close(ctx)
	rows := make([]Account, 0, limit+1)
	for cursor.Next(ctx) {
		var row Account
		if err := cursor.Decode(&row); err != nil {
			return Page{}, err
		}
		if !subjectPattern.MatchString(row.Subject) || row.Name == "" || row.CreatedAt.IsZero() {
			return Page{}, ErrInvalid
		}
		rows = append(rows, row)
	}
	if err := cursor.Err(); err != nil {
		return Page{}, err
	}
	page := Page{Accounts: rows}
	if len(rows) > limit {
		page.Accounts = rows[:limit]
		page.Next = rows[limit-1].Subject
	}
	return page, nil
}
