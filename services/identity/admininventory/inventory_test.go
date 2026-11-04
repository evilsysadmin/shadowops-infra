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
	for _, tc := range []struct {
		cursor string
		limit  int
	}{{"", 0}, {"", 51}, {"bad", 1}} {
		if _, err := inventory.List(ctx, tc.cursor, tc.limit); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid request accepted", tc)
		}
	}
}
