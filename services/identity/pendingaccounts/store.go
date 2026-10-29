// Package pendingaccounts reserves immutable staging subjects and one explicitly
// reviewed legacy identity link. Pending records cannot authenticate users.
package pendingaccounts

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	StagingDatabase = "shadowops_identity_staging"
	collectionName = "pending_accounts"
	pendingState = "pending-review"
)

var (
	ErrInvalid = errors.New("invalid identity staging account reservation")
	ErrConflict = errors.New("identity staging account reservation conflict")
	subjectRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reviewRe = regexp.MustCompile(`^https://github[.]com/evilsysadmin/shadowops-infra/issues/[1-9][0-9]*$`)
)

type Reservation struct {
	Subject string
	Source string
	LegacyUsername string
	ReviewRef string
}

type Store struct { accounts *mongo.Collection }

type document struct {
	Subject string `bson:"_id"`
	Environment string `bson:"environment"`
	State string `bson:"state"`
	Source string `bson:"source"`
	LegacyUsername string `bson:"legacy_username"`
	AliasKey string `bson:"alias_key"`
	ReviewRef string `bson:"review_ref"`
	CreatedAt time.Time `bson:"created_at"`
}

// normalize matches the Python preflight's NFKC + casefold rule for common
// legacy aliases, including case-only and Unicode compatibility collisions.
func normalizedUsername(name string) (string, bool) {
	if name == "" || name != strings.TrimSpace(name) || !utf8.ValidString(name) ||
		utf8.RuneCountInString(name) > 80 {
		return "", false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) { return "", false }
	}
	key := cases.Fold().String(norm.NFKC.String(name))
	if key == "" { return "", false }
	return key, true
}

func validReservation(r Reservation) (string, bool) {
	if !subjectRe.MatchString(r.Subject) ||
		(r.Source != "chess-studio" && r.Source != "chronicles") ||
		!reviewRe.MatchString(r.ReviewRef) {
		return "", false
	}
	return normalizedUsername(r.LegacyUsername)
}

// New refuses production and game databases and creates indexes before any
// pending reservation can be persisted. No account-authentication API exists.
func New(ctx context.Context, db *mongo.Database) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || db.Name() != StagingDatabase {
		return nil, ErrInvalid
	}
	col := db.Collection(collectionName,
		options.Collection().SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	_, err := col.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "environment", Value: 1}, {Key: "source", Value: 1}, {Key: "alias_key", Value: 1}},
			Options: options.Index().SetUnique(true).SetName("staging_source_alias_unique")},
		{Keys: bson.D{{Key: "review_ref", Value: 1}},
			Options: options.Index().SetName("pending_review_reference")},
	})
	if err != nil { return nil, err }
	return &Store{accounts: col}, nil
}

// ReservePending is intentionally insert-only and keeps a single source link
// per subject. Even with a shared review ticket, Chess and Chronicles users
// are NEVER automatically merged. A ticket is a reference, NOT proof of
// ownership; this method must not be wired to public account import/login.
func (s *Store) ReservePending(ctx context.Context, r Reservation) error {
	key, ok := validReservation(r)
	if s == nil || s.accounts == nil || ctx == nil || ctx.Err() != nil || !ok {
		return ErrInvalid
	}
	_, err := s.accounts.InsertOne(ctx, document{
		Subject: r.Subject,
		Environment: "staging",
		State: pendingState,
		Source: r.Source,
		LegacyUsername: r.LegacyUsername,
		AliasKey: key,
		ReviewRef: r.ReviewRef,
		CreatedAt: time.Now().UTC(),
	})
	if mongo.IsDuplicateKeyError(err) { return ErrConflict }
	return err
}

// FindPending returns metadata only: no email, password hash, authentication
// flag, roles or permissions are present in this collection.
func (s *Store) FindPending(ctx context.Context, subject string) (Reservation, bool, error) {
	if s == nil || s.accounts == nil || ctx == nil || ctx.Err() != nil || !subjectRe.MatchString(subject) {
		return Reservation{}, false, ErrInvalid
	}
	var d document
	err := s.accounts.FindOne(ctx, bson.D{
		{Key: "_id", Value: subject},
		{Key: "environment", Value: "staging"},
		{Key: "state", Value: pendingState},
	}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) { return Reservation{}, false, nil }
	if err != nil { return Reservation{}, false, err }
	r := Reservation{Subject: d.Subject, Source: d.Source, LegacyUsername: d.LegacyUsername, ReviewRef: d.ReviewRef}
	key, ok := validReservation(r)
	if !ok || d.AliasKey != key || d.Environment != "staging" || d.State != pendingState {
		return Reservation{}, false, ErrInvalid
	}
	return r, true, nil
}
