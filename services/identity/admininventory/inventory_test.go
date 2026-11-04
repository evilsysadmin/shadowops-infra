package admininventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestInventoryStagingPaginationAndIsolation(t *testing.T) {
	uri := os.Getenv("IDENTITY_INVENTORY_TEST_MONGO")
	if uri == "" {
		t.Skip("disposable MongoDB fixture not configured")
	}
	if uri != "mongodb://127.0.0.1:27097" {
		t.Fatal("fixture must be the dedicated loopback MongoDB")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	db := client.Database("shadowops_identity_staging")
	if _, err := NewStaging(client.Database("production")); !errors.Is(err, ErrInvalid) {
		t.Fatal("production accepted")
	}
	collection := db.Collection("pending_accounts")
	ids := []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"}
	docs := []any{}
	for index, id := range ids {
		source := "shadowops-identity"
		environment := "staging"
		if index == 2 {
			source = "chess-studio"
		}
		if index == 3 {
			environment = "production"
		}
		docs = append(docs, bson.M{"_id": id, "environment": environment, "source": source, "alias_key": "player", "state": "active", "credentials_disabled": index == 1, "session_version": int64(2), "created_at": time.Now(), "credential_hash": "secret-hash", "recovery_digest": "secret-recovery"})
	}
	if _, err := collection.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = collection.DeleteMany(context.Background(), bson.M{"_id": bson.M{"$in": ids}})
	})
	now := time.Now().UTC()
	sessions := db.Collection("sessions")
	sessionDocs := []any{
		bson.M{"_id": "inventory-current", "environment": "staging", "subject": ids[0], "session_version": int64(2), "issued_at": now, "expires_at": now.Add(time.Hour), "digest": "secret-session"},
		bson.M{"_id": "inventory-old-version", "environment": "staging", "subject": ids[0], "session_version": int64(1), "issued_at": now, "expires_at": now.Add(time.Hour)},
		bson.M{"_id": "inventory-expired", "environment": "staging", "subject": ids[0], "session_version": int64(2), "issued_at": now.Add(-time.Hour), "expires_at": now.Add(-time.Minute)},
		bson.M{"_id": "inventory-too-long", "environment": "staging", "subject": ids[0], "session_version": int64(2), "issued_at": now, "expires_at": now.Add(25 * time.Hour)},
		bson.M{"_id": "inventory-other-env", "environment": "production", "subject": ids[0], "session_version": int64(2), "issued_at": now, "expires_at": now.Add(time.Hour)},
		bson.M{"_id": "inventory-disabled", "environment": "staging", "subject": ids[1], "session_version": int64(2), "issued_at": now, "expires_at": now.Add(time.Hour)},
	}
	if _, err := sessions.InsertMany(ctx, sessionDocs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = sessions.DeleteMany(context.Background(), bson.M{"_id": bson.M{"$in": []string{"inventory-current", "inventory-old-version", "inventory-expired", "inventory-too-long", "inventory-other-env", "inventory-disabled"}}})
	})
	inventory, err := NewStaging(db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := inventory.List(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Accounts) != 1 || first.Accounts[0].Subject != ids[0] || first.Accounts[0].CurrentSessions != 1 || first.Next != ids[0] {
		t.Fatalf("unexpected first page: %+v", first)
	}
	next, err := inventory.List(ctx, first.Next, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Accounts) != 1 || next.Accounts[0].Subject != ids[1] || next.Accounts[0].CurrentSessions != 0 || next.Next != "" {
		t.Fatalf("unexpected second page: %+v", next)
	}
	encoded, _ := json.Marshal(first)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("credential material exposed")
	}
	if first.RecentAccessAvailable {
		t.Fatal("recent access enabled without explicit configuration")
	}
	tokens := db.Collection("staging_cka_tokens")
	if err := db.RunCommand(ctx, bson.D{{Key: "create", Value: "staging_admin_recent_access"}, {Key: "viewOn", Value: "staging_cka_tokens"}, {Key: "pipeline", Value: bson.A{bson.D{{Key: "$project", Value: bson.D{{Key: "_id", Value: 0}, {Key: "issuer", Value: 1}, {Key: "subject", Value: 1}, {Key: "session_version", Value: 1}, {Key: "audience", Value: 1}, {Key: "issued_at", Value: 1}}}}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Collection("staging_admin_recent_access").Drop(context.Background()) })
	tokenIDs := []string{"recent-chronicles", "recent-duplicate", "recent-football", "recent-old", "recent-other-env", "recent-invalid-app", "recent-old-version"}
	rows := []any{}
	for index, id := range tokenIDs {
		issuer, app, issued, version := "https://id-staging.shadowops.dpdns.org", "chronicles", now, int64(2)
		switch index {
		case 2:
			app = "football"
		case 3:
			issued = now.Add(-3 * time.Minute)
		case 4:
			issuer = "https://production.invalid"
		case 5:
			app = "unknown"
		case 6:
			version = 1
		}
		rows = append(rows, bson.M{"_id": id, "issuer": issuer, "audience": app, "subject": ids[0], "session_version": version, "issued_at": issued, "session_digest": "secret-digest"})
	}
	if _, err := tokens.InsertMany(ctx, rows); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = tokens.DeleteMany(context.Background(), bson.M{"_id": bson.M{"$in": tokenIDs}}) })
	withAccess, err := NewStagingWithRecentAccess(db)
	if err != nil {
		t.Fatal(err)
	}
	withPage, err := withAccess.List(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !withPage.RecentAccessAvailable || len(withPage.Accounts[0].RecentApplications) != 2 {
		t.Fatalf("unexpected recent access: %+v", withPage)
	}
	appNames := map[string]bool{}
	for _, app := range withPage.Accounts[0].RecentApplications {
		appNames[app.Application] = true
	}
	if !appNames["chronicles"] || !appNames["football"] {
		t.Fatal("wrong recent applications", appNames)
	}
	encoded, _ = json.Marshal(withPage)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("token data exposed")
	}
	if withPage.AccessHistoryAvailable {
		t.Fatal("history enabled without explicit configuration")
	}
	history := db.Collection("staging_application_access_history")
	historyIDs := []string{"history-chronicles", "history-disabled", "history-other-env", "history-unknown"}
	old := now.Add(-90 * 24 * time.Hour)
	if _, err := history.InsertMany(ctx, []any{
		bson.M{"_id": historyIDs[0], "environment": "staging", "subject": ids[0], "application": "chronicles", "first_at": old, "last_at": old.Add(time.Hour), "private": "secret"},
		bson.M{"_id": historyIDs[1], "environment": "staging", "subject": ids[1], "application": "football", "first_at": old, "last_at": old},
		bson.M{"_id": historyIDs[2], "environment": "production", "subject": ids[0], "application": "football", "first_at": old, "last_at": old},
		bson.M{"_id": historyIDs[3], "environment": "staging", "subject": ids[0], "application": "unknown", "first_at": old, "last_at": old},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = history.DeleteMany(context.Background(), bson.M{"_id": bson.M{"$in": historyIDs}}) })
	withHistory, err := withAccess.WithAccessHistory(db)
	if err != nil {
		t.Fatal(err)
	}
	historyPage, err := withHistory.List(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !historyPage.AccessHistoryAvailable || len(historyPage.Accounts[0].AccessHistory) != 1 || historyPage.Accounts[0].AccessHistory[0].Application != "chronicles" || !historyPage.Accounts[0].AccessHistory[0].FirstAt.Equal(old.Truncate(time.Millisecond)) {
		t.Fatal("history missing or wrong", historyPage)
	}
	disabledPage, err := withHistory.List(ctx, historyPage.Next, 1)
	if err != nil || len(disabledPage.Accounts[0].AccessHistory) != 1 {
		t.Fatal("disabled account history missing", err)
	}
	encoded, _ = json.Marshal(historyPage)
	if strings.Contains(string(encoded), "secret") {
		t.Fatal("private history field exposed")
	}
	for _, tc := range []struct {
		cursor string
		limit  int
	}{{"", 0}, {"", 51}, {"bad", 1}} {
		if _, err := inventory.List(ctx, tc.cursor, tc.limit); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid request accepted", tc)
		}
	}
}
