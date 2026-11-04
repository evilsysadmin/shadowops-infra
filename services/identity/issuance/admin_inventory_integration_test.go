package issuance

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestStagingAdminInventoryRequiresCurrentAdminSessionAndAudits(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	audit := db.Collection("admin_inventory_audit")
	if err := audit.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = audit.Drop(context.Background()) })
	_, err := db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": alice}, bson.M{"$set": bson.M{"source": "shadowops-identity", "alias_key": "alice", "created_at": time.Now().UTC(), "role": "user"}})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.StagingAdminInventory(ctx, handle, "", 10); !errors.Is(err, ErrDenied) {
		t.Fatal("ordinary user allowed", err)
	}
	count, err := audit.CountDocuments(ctx, bson.M{})
	if err != nil || count != 0 {
		t.Fatal("denied read was audited as success", err)
	}
	_, err = db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": alice}, bson.M{"$set": bson.M{"role": "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := issuer.StagingAdminInventory(ctx, handle, "", 10)
	if err != nil || len(page.Accounts) != 1 || page.Accounts[0].Subject != alice || page.Accounts[0].CurrentSessions != 1 {
		t.Fatalf("authorized inventory failed: %+v %v", page, err)
	}
	var entry struct {
		Actor    string `bson:"actor"`
		Action   string `bson:"action"`
		Returned int    `bson:"returned"`
	}
	if err := audit.FindOne(ctx, bson.M{}).Decode(&entry); err != nil || entry.Actor != alice || entry.Action != "list_accounts" || entry.Returned != 1 {
		t.Fatal("missing audit event", err)
	}
	issuer.afterFence = func() error { return errors.New("synthetic failure") }
	if _, err := issuer.StagingAdminInventory(ctx, handle, "", 10); !errors.Is(err, ErrStore) {
		t.Fatal("failed transaction returned data", err)
	}
	issuer.afterFence = nil
	count, err = audit.CountDocuments(ctx, bson.M{})
	if err != nil || count != 1 {
		t.Fatal("failed read committed audit", count, err)
	}
	rotated, err := issuer.Refresh(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.StagingAdminInventory(ctx, handle, "", 10); !errors.Is(err, ErrDenied) {
		t.Fatal("rotated session accepted", err)
	}
	_, err = db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": alice}, bson.M{"$set": bson.M{"role": "user"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.StagingAdminInventory(ctx, rotated, "", 10); !errors.Is(err, ErrDenied) {
		t.Fatal("demoted account accepted", err)
	}
	count, err = audit.CountDocuments(ctx, bson.M{})
	if err != nil || count != 1 {
		t.Fatal("unexpected audit count", count, err)
	}
}
