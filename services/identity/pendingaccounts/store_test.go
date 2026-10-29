package pendingaccounts

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	chessUUID = "11111111-1111-4111-8111-111111111111"
	chroniclesUUID = "22222222-2222-4222-8222-222222222222"
	reviewURL = "https://github.com/evilsysadmin/shadowops-infra/issues/287"
)

func TestOfflineValidationIsFailClosed(t *testing.T) {
	for _, env := range []string{"", "staging", "production"} {
		_ = env
	}
	if _, err := New(context.Background(), nil); !errors.Is(err, ErrInvalid) { t.Fatal("nil database accepted") }
	var store *Store
	if err := store.ReservePending(context.Background(), Reservation{}); !errors.Is(err, ErrInvalid) { t.Fatal("nil store allowed reserve") }
	if _, _, err := store.FindPending(context.Background(), chessUUID); !errors.Is(err, ErrInvalid) { t.Fatal("nil store allowed lookup") }
	valid := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if _, ok := validReservation(valid); !ok { t.Fatal("valid synthetic reservation refused") }
	invalid := []Reservation{
		{Subject: "matthias", Source: valid.Source, LegacyUsername: valid.LegacyUsername, ReviewRef: reviewURL},
		{Subject: chessUUID, Source: "unknown", LegacyUsername: valid.LegacyUsername, ReviewRef: reviewURL},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: "", ReviewRef: reviewURL},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: " Matthias", ReviewRef: reviewURL},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: "Matthias\n", ReviewRef: reviewURL},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: "Matthias", ReviewRef: ""},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: "Matthias", ReviewRef: "https://evil.example/287"},
		{Subject: chessUUID, Source: valid.Source, LegacyUsername: "Matthias", ReviewRef: "https://github.com/evilsysadmin/shadowops-infra/issues/000287"},
	}
	for i, r := range invalid {
		if _, ok := validReservation(r); ok { t.Errorf("accepted invalid reservation %d", i) }
	}
	one, _ := normalizedUsername("Straße")
	two, _ := normalizedUsername("STRASSE")
	if one != two { t.Fatal("Unicode casefold failed") }
	a, _ := normalizedUsername("Knight")
	b, _ := normalizedUsername("knight")
	if a != b { t.Fatal("NFKC normalization failed") }
}

func disposableDB(t *testing.T) (*mongo.Client, *mongo.Database) {
	t.Helper()
	uri := os.Getenv("IDENTITY_MONGO_TEST_URL")
	if uri == "" { t.Skip("No disposable MongoDB configured") }
	if uri != "mongodb://127.0.0.1:27017" { t.Fatal("refusing non-local MongoDB") }
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil { t.Fatal(err) }
	if err := client.Ping(ctx, nil); err != nil { t.Fatal(err) }
	db := client.Database(StagingDatabase)
	if err := db.Collection(collectionName).Drop(ctx); err != nil { t.Fatal(err) }
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = db.Collection(collectionName).Drop(c)
		_ = client.Disconnect(c)
	})
	return client, db
}

func TestMongoReservationsNoImplicitCrossProductMerge(t *testing.T) {
	client, db := disposableDB(t)
	ctx := context.Background()
	store, err := New(ctx, db)
	if err != nil { t.Fatal(err) }
	for _, name := range []string{"shadowops_identity_production", "chess_studio", "chronicles"} {
		if _, err := New(ctx, client.Database(name)); !errors.Is(err, ErrInvalid) { t.Fatal("allowed unrelated DB", name) }
	}
	indexCursor, err := db.Collection(collectionName).Indexes().List(ctx)
	if err != nil { t.Fatal(err) }
	var indexes []bson.M
	if err := indexCursor.All(ctx, &indexes); err != nil { t.Fatal(err) }
	if len(indexes) != 3 { t.Fatalf("missing identity uniqueness indexes: %d", len(indexes)) }

	chess := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Straße", ReviewRef: reviewURL}
	chronicles := Reservation{Subject: chroniclesUUID, Source: "chronicles", LegacyUsername: "STRASSE", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, chess); err != nil { t.Fatal(err) }
	if err := store.ReservePending(ctx, chronicles); err != nil { t.Fatal("same username across games must not auto-merge", err) }
	if _, found, err := store.FindPending(ctx, chess.Subject); err != nil || !found { t.Fatal("first reservation lost", err) }
	if _, found, err := store.FindPending(ctx, chronicles.Subject); err != nil || !found { t.Fatal("second reservation lost", err) }
	// Same-name collision within one product must lose, including Unicode aliases.
	collision := Reservation{Subject: "33333333-3333-4333-8333-333333333333", Source: "chess-studio", LegacyUsername: "STRASSE", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, collision); !errors.Is(err, ErrConflict) { t.Fatal("Unicode alias collision accepted", err) }
	// Shared UUID across different games is NEVER implicitly merged.
	sameSubject := Reservation{Subject: chessUUID, Source: "chronicles", LegacyUsername: "Other", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, sameSubject); !errors.Is(err, ErrConflict) { t.Fatal("cross-source UUID merge accepted", err) }
	if err := store.ReservePending(ctx, chess); !errors.Is(err, ErrConflict) { t.Fatal("duplicate insert accepted", err) }

	var raw bson.M
	if err := db.Collection(collectionName).FindOne(ctx, bson.D{{Key: "_id", Value: chessUUID}}).Decode(&raw); err != nil { t.Fatal(err) }
	for _, forbidden := range []string{"password_hash", "email", "roles", "is_active", "session_version"} {
		if _, exists := raw[forbidden]; exists { t.Fatal("pending reservation stores active credential/permission field") }
	}
	if raw["state"] != pendingState || raw["environment"] != "staging" { t.Fatal("unexpected account state") }
}

func TestMongoReadPendingRejectsWrongState(t *testing.T) {
	_, db := disposableDB(t)
	ctx := context.Background()
	store, err := New(ctx, db)
	if err != nil { t.Fatal(err) }
	r := Reservation{Subject: chessUUID, Source: "chess-studio", LegacyUsername: "Matthias", ReviewRef: reviewURL}
	if err := store.ReservePending(ctx, r); err != nil { t.Fatal(err) }
	if _, err := db.Collection(collectionName).UpdateOne(ctx, bson.D{{Key: "_id", Value: chessUUID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "state", Value: "active"}}}}); err != nil { t.Fatal(err) }
	if _, found, err := store.FindPending(ctx, chessUUID); err != nil || found { t.Fatal("active account treated as pending", err) }
}
