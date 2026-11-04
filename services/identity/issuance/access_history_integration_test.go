package issuance

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestAccessHistoryRecordsCommittedExchangesOnly(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	history := db.Collection("staging_application_access_history")
	if err := history.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = history.Drop(context.Background()) })
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewStagingAppSigner(issuer, bytes.Repeat([]byte{0x44}, 32), Chronicles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.IssueToken(ctx, handle); err != nil {
		t.Fatal(err)
	}
	count, err := history.CountDocuments(ctx, bson.M{})
	if err != nil || count != 0 {
		t.Fatal("default recording was enabled", count, err)
	}
	if err := issuer.EnableStagingAccessHistory(); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.IssueToken(ctx, handle); err != nil {
		t.Fatal(err)
	}
	var before struct {
		First   time.Time `bson:"first_at"`
		Last    time.Time `bson:"last_at"`
		Subject string    `bson:"subject"`
		App     string    `bson:"application"`
	}
	if err := history.FindOne(ctx, bson.M{}).Decode(&before); err != nil {
		t.Fatal(err)
	}
	if before.Subject != alice || before.App != "chronicles" || before.First.IsZero() || !before.First.Equal(before.Last) {
		t.Fatal("wrong initial summary", before)
	}
	if _, err := signer.IssueToken(ctx, handle); err != nil {
		t.Fatal(err)
	}
	var after struct {
		First time.Time `bson:"first_at"`
		Last  time.Time `bson:"last_at"`
	}
	if err := history.FindOne(ctx, bson.M{}).Decode(&after); err != nil || !after.First.Equal(before.First) || after.Last.Before(before.Last) {
		t.Fatal("summary did not preserve first and last", after, err)
	}
	if _, err := signer.IssueToken(ctx, "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid session accepted", err)
	}
	if err := issuer.Logout(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.IssueToken(ctx, handle); !errors.Is(err, ErrDenied) {
		t.Fatal("logged-out session accepted", err)
	}
	count, err = history.CountDocuments(ctx, bson.M{})
	if err != nil || count != 1 {
		t.Fatal("unexpected records", count, err)
	}
}

func TestAccessHistoryFailureRollsBackTokenExchange(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	history := db.Collection("staging_application_access_history")
	if err := history.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = history.Drop(context.Background()) })
	validator := bson.M{"$jsonSchema": bson.M{"required": bson.A{"synthetic_required_field"}}}
	if err := db.CreateCollection(ctx, "staging_application_access_history", options.CreateCollection().SetValidator(validator)); err != nil {
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
	if err := issuer.EnableStagingAccessHistory(); err != nil {
		t.Fatal(err)
	}
	signer, err := NewStagingAppSigner(issuer, bytes.Repeat([]byte{0x44}, 32), Chronicles)
	if err != nil {
		t.Fatal(err)
	}
	if token, err := signer.IssueToken(ctx, handle); token != "" || !errors.Is(err, ErrStore) {
		t.Fatal("history failure did not deny exchange", err)
	}
	count, err := db.Collection(appTokenCollection).CountDocuments(ctx, bson.M{})
	if err != nil || count != 0 {
		t.Fatal("failed exchange left a token record", count, err)
	}
}
