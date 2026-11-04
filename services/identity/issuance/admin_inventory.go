package issuance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/admininventory"
	"github.com/evilsysadmin/shadowops-infra/services/identity/mongostore"
	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

// StagingAdminInventoryReader exposes only the inventory transaction, not
// registration or session issuance, for a dedicated database principal.
type StagingAdminInventoryReader struct{ issuer *Issuer }

func NewStagingAdminInventoryReader(client *mongo.Client, recentAccess bool) (*StagingAdminInventoryReader, error) {
	if client == nil {
		return nil, ErrDenied
	}
	db := client.Database(stagingDatabase)
	store, err := mongostore.OpenExistingStaging(db)
	if err != nil {
		return nil, ErrStore
	}
	return &StagingAdminInventoryReader{issuer: &Issuer{client: client, accounts: db.Collection("pending_accounts"), sessions: store, adminRecentAccess: recentAccess}}, nil
}

func (r *StagingAdminInventoryReader) StagingAdminInventory(ctx context.Context, handle, after string, limit int) (admininventory.Page, error) {
	if r == nil {
		return admininventory.Page{}, ErrDenied
	}
	return r.issuer.StagingAdminInventory(ctx, handle, after, limit)
}

// StagingAdminInventory authenticates an opaque central session and reads the
// inventory only for a native active platform admin. It records the successful
// read and fences both account and session in the same majority transaction.
// It is an internal primitive: transport, rate limits, and an independently
// provisioned least-privilege database principal must be established before use.
func (i *Issuer) StagingAdminInventory(ctx context.Context, handle, after string, limit int) (admininventory.Page, error) {
	if i == nil || i.client == nil || i.accounts == nil || i.sessions == nil || ctx == nil || ctx.Err() != nil {
		return admininventory.Page{}, ErrDenied
	}
	digest, ok := stagingHandleDigest(handle)
	if !ok {
		return admininventory.Page{}, ErrDenied
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return admininventory.Page{}, ErrStore
	}
	id := hex.EncodeToString(nonce[:])
	db := i.client.Database(stagingDatabase)
	inventory, err := admininventory.NewStaging(db)
	if i.adminRecentAccess {
		inventory, err = admininventory.NewStagingWithRecentAccess(db)
	}
	if err != nil {
		return admininventory.Page{}, ErrStore
	}
	txn, err := i.client.StartSession()
	if err != nil {
		return admininventory.Page{}, ErrStore
	}
	defer txn.EndSession(context.Background())
	opts := options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	var page admininventory.Page
	_, err = txn.WithTransaction(ctx, func(tx context.Context) (any, error) {
		rec, exists, err := i.sessions.Get(tx, "staging", digest)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if !exists || rec.Digest != digest || rec.Environment != "staging" || !uuidV4.MatchString(rec.Subject) || rec.SessionVersion <= 0 || !rec.IssuedAt.Before(rec.ExpiresAt) || rec.IssuedAt.After(now.Add(30*time.Second)) || rec.ExpiresAt.Sub(rec.IssuedAt) > session.Lifetime || !now.Before(rec.ExpiresAt) {
			return nil, ErrDenied
		}
		account, err := i.accounts.UpdateOne(tx, bson.D{{Key: "_id", Value: rec.Subject}, {Key: "environment", Value: "staging"}, {Key: "source", Value: "shadowops-identity"}, {Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}, {Key: "role", Value: "admin"}, {Key: "session_version", Value: rec.SessionVersion}}, bson.D{{Key: "$inc", Value: bson.D{{Key: "admin_read_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if account.ModifiedCount != 1 {
			return nil, ErrDenied
		}
		// A write to the exact session conflicts with concurrent logout/refresh.
		sessionResult, err := db.Collection("sessions").UpdateOne(tx, bson.D{{Key: "environment", Value: "staging"}, {Key: "digest", Value: hex.EncodeToString(digest[:])}, {Key: "subject", Value: rec.Subject}, {Key: "session_version", Value: rec.SessionVersion}, {Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}}}, bson.D{{Key: "$inc", Value: bson.D{{Key: "admin_read_fence", Value: int64(1)}}}})
		if err != nil {
			return nil, err
		}
		if sessionResult.ModifiedCount != 1 {
			return nil, ErrDenied
		}
		if i.afterFence != nil {
			if err := i.afterFence(); err != nil {
				return nil, err
			}
		}
		page, err = inventory.List(tx, after, limit)
		if err != nil {
			return nil, err
		}
		_, err = db.Collection("admin_inventory_audit").InsertOne(tx, bson.D{{Key: "_id", Value: id}, {Key: "environment", Value: "staging"}, {Key: "actor", Value: rec.Subject}, {Key: "action", Value: "list_accounts"}, {Key: "at", Value: now}, {Key: "returned", Value: len(page.Accounts)}})
		if err != nil {
			return nil, err
		}
		return nil, nil
	}, opts)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, admininventory.ErrInvalid) {
			return admininventory.Page{}, ErrDenied
		}
		return admininventory.Page{}, ErrStore
	}
	return page, nil
}
