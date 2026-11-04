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
	Subject             string              `json:"subject" bson:"_id"`
	Name                string              `json:"name" bson:"alias_key"`
	State               string              `json:"state" bson:"state"`
	CredentialsDisabled bool                `json:"credentialsDisabled" bson:"credentials_disabled"`
	CreatedAt           time.Time           `json:"createdAt" bson:"created_at"`
	CurrentSessions     int64               `json:"currentSessions" bson:"-"`
	SessionVersion      int64               `json:"-" bson:"session_version"`
	RecentApplications  []RecentApplication `json:"recentApplications,omitempty" bson:"-"`
}

// RecentApplication is a recent Identity token exchange, not proof of play.
type RecentApplication struct {
	Application string    `json:"application" bson:"application"`
	At          time.Time `json:"at" bson:"at"`
}

type Page struct {
	Accounts              []Account `json:"accounts"`
	Next                  string    `json:"next,omitempty"`
	RecentAccessAvailable bool      `json:"recentAccessAvailable"`
}

type Inventory struct{ accounts, sessions, tokens *mongo.Collection }

// NewStaging accepts only the fixed staging database. Its Mongo principal must
// have find-only access to pending_accounts and sessions and be provisioned separately
// from the public Identity runtime.
func NewStaging(db *mongo.Database) (*Inventory, error) {
	if db == nil || db.Name() != "shadowops_identity_staging" {
		return nil, ErrInvalid
	}
	return &Inventory{accounts: db.Collection("pending_accounts"), sessions: db.Collection("sessions")}, nil
}

// NewStagingWithRecentAccess additionally reads short-lived token records.
func NewStagingWithRecentAccess(db *mongo.Database) (*Inventory, error) {
	inventory, err := NewStaging(db)
	if err != nil {
		return nil, err
	}
	inventory.tokens = db.Collection("staging_admin_recent_access")
	return inventory, nil
}

// List returns at most 50 native accounts in stable subject order. The cursor
// is the last returned UUID; no name or secret is embedded in it. Legacy
// reservations are intentionally excluded and accounts are never matched by name.
func (i *Inventory) List(ctx context.Context, after string, limit int) (Page, error) {
	if i == nil || i.accounts == nil || i.sessions == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > 50 || (after != "" && !subjectPattern.MatchString(after)) {
		return Page{}, ErrInvalid
	}
	filter := bson.D{{Key: "environment", Value: "staging"}, {Key: "source", Value: "shadowops-identity"}}
	if after != "" {
		filter = append(filter, bson.E{Key: "_id", Value: bson.D{{Key: "$gt", Value: after}}})
	}
	opts := options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}, {Key: "alias_key", Value: 1}, {Key: "state", Value: 1}, {Key: "credentials_disabled", Value: 1}, {Key: "created_at", Value: 1}, {Key: "session_version", Value: 1}}).SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(int64(limit + 1))
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
	page := Page{Accounts: rows, RecentAccessAvailable: i.tokens != nil}
	if len(rows) > limit {
		page.Accounts = rows[:limit]
		page.Next = rows[limit-1].Subject
	}
	// Count only unexpired records whose version still matches an eligible
	// account. Session rotation changes issued_at, so this is not login history.
	var pairs bson.A
	for _, account := range page.Accounts {
		if account.State == "active" && !account.CredentialsDisabled && account.SessionVersion > 0 {
			pairs = append(pairs, bson.D{{Key: "subject", Value: account.Subject}, {Key: "session_version", Value: account.SessionVersion}})
		}
	}
	if len(pairs) == 0 {
		return page, nil
	}
	now := time.Now().UTC()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "environment", Value: "staging"}, {Key: "$or", Value: pairs}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}}, {Key: "issued_at", Value: bson.D{{Key: "$lte", Value: now.Add(30 * time.Second)}}}, {Key: "$expr", Value: bson.D{{Key: "$and", Value: bson.A{bson.D{{Key: "$lt", Value: bson.A{"$issued_at", "$expires_at"}}}, bson.D{{Key: "$lte", Value: bson.A{bson.D{{Key: "$subtract", Value: bson.A{"$expires_at", "$issued_at"}}}, int64((24 * time.Hour) / time.Millisecond)}}}}}}}}}},
		{{Key: "$group", Value: bson.D{{Key: "_id", Value: "$subject"}, {Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}}}}},
	}
	sessions, err := i.sessions.Aggregate(ctx, pipeline)
	if err != nil {
		return Page{}, err
	}
	defer sessions.Close(ctx)
	counts := make(map[string]int64, len(pairs))
	for sessions.Next(ctx) {
		var result struct {
			Subject string `bson:"_id"`
			Count   int64  `bson:"count"`
		}
		if err := sessions.Decode(&result); err != nil {
			return Page{}, err
		}
		counts[result.Subject] = result.Count
	}
	if err := sessions.Err(); err != nil {
		return Page{}, err
	}
	for index := range page.Accounts {
		page.Accounts[index].CurrentSessions = counts[page.Accounts[index].Subject]
	}
	if i.tokens != nil {
		apps := bson.A{"chess-studio", "chronicles", "cka-simulator", "football", "pawn-action"}
		pipeline := mongo.Pipeline{
			{{Key: "$match", Value: bson.D{{Key: "issuer", Value: "https://id-staging.shadowops.dpdns.org"}, {Key: "$or", Value: pairs}, {Key: "audience", Value: bson.D{{Key: "$in", Value: apps}}}, {Key: "issued_at", Value: bson.D{{Key: "$gte", Value: now.Add(-2 * time.Minute)}, {Key: "$lte", Value: now.Add(30 * time.Second)}}}}}},
			{{Key: "$group", Value: bson.D{{Key: "_id", Value: bson.D{{Key: "subject", Value: "$subject"}, {Key: "application", Value: "$audience"}}}, {Key: "at", Value: bson.D{{Key: "$max", Value: "$issued_at"}}}}}},
			{{Key: "$sort", Value: bson.D{{Key: "at", Value: -1}, {Key: "_id.application", Value: 1}}}},
		}
		cursor, err := i.tokens.Aggregate(ctx, pipeline)
		if err != nil {
			return Page{}, err
		}
		defer cursor.Close(ctx)
		perAccount := make(map[string][]RecentApplication, len(page.Accounts))
		for cursor.Next(ctx) {
			var result struct {
				ID struct {
					Subject     string `bson:"subject"`
					Application string `bson:"application"`
				} `bson:"_id"`
				At time.Time `bson:"at"`
			}
			if err := cursor.Decode(&result); err != nil {
				return Page{}, err
			}
			perAccount[result.ID.Subject] = append(perAccount[result.ID.Subject], RecentApplication{Application: result.ID.Application, At: result.At})
		}
		if err := cursor.Err(); err != nil {
			return Page{}, err
		}
		for index := range page.Accounts {
			page.Accounts[index].RecentApplications = perAccount[page.Accounts[index].Subject]
		}
	}
	return page, nil
}
