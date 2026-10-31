package issuance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"github.com/evilsysadmin/shadowops-infra/services/identity/roles"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const nativeSource = "shadowops-identity"

var ErrNameUnavailable = errors.New("central account name unavailable")
var nativeName = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)

// NativeAccounts enrolls NEW central accounts, never imported reservations.
// All lookups include the native source. A matching legacy name grants no
// ownership, saved games, roles or activation of that legacy record.
type NativeAccounts struct {
	issuer   *Issuer
	accounts *mongo.Collection
}

func NewStagingNativeAccounts(ctx context.Context, issuer *Issuer) (*NativeAccounts, error) {
	if ctx == nil || ctx.Err() != nil || issuer == nil || issuer.client == nil || issuer.accounts == nil || issuer.sessions == nil {
		return nil, ErrDenied
	}
	accounts := issuer.client.Database(stagingDatabase).Collection("pending_accounts", options.Collection().
		SetReadConcern(readconcern.Majority()).SetReadPreference(readpref.Primary()).SetWriteConcern(writeconcern.Majority()))
	// Same index as the reservations adapter. The source partitions native
	// names from legacy aliases; native creation is insert-only with a new UUID.
	_, err := accounts.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "environment", Value: 1}, {Key: "source", Value: 1}, {Key: "alias_key", Value: 1}},
		Options: options.Index().SetUnique(true).SetName("staging_source_alias_unique"),
	})
	if err != nil {
		return nil, ErrStore
	}
	return &NativeAccounts{issuer: issuer, accounts: accounts}, nil
}

func centralName(input string) (string, bool) {
	if len(input) > 80 {
		return "", false
	}
	for _, b := range []byte(input) {
		if b > 127 {
			return "", false
		}
	}
	name := strings.ToLower(strings.TrimSpace(input))
	return name, nativeName.MatchString(name)
}

func newRecovery() (string, string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", ErrStore
	}
	code := "sor1_" + base64.RawURLEncoding.EncodeToString(raw[:])
	digest, _ := recoveryDigest(code)
	return code, digest, nil
}

func recoveryDigest(code string) (string, bool) {
	if len(code) != 48 || !strings.HasPrefix(code, "sor1_") {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(code[5:])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != code[5:] {
		return "", false
	}
	d := sha256.Sum256([]byte("shadowops-recovery-v1:staging:" + code))
	return hex.EncodeToString(d[:]), true
}

func (n *NativeAccounts) ready(ctx context.Context) bool {
	return n != nil && n.issuer != nil && n.accounts != nil && ctx != nil && ctx.Err() == nil
}

func validNewPassword(candidate string) bool {
	return len(candidate) <= 4096 && utf8.ValidString(candidate) && utf8.RuneCountInString(candidate) >= 15
}

// Register returns a recovery secret ONCE, only after a majority insert. The
// secret is never stored, logged or emailed; its domain-separated digest is.
// It does not create a browser session or any product account/privilege.
func (n *NativeAccounts) Register(ctx context.Context, input, candidate string) (string, error) {
	name, valid := centralName(input)
	if !n.ready(ctx) || !valid || !validNewPassword(candidate) {
		return "", ErrDenied
	}
	hash, err := password.HashNew(candidate)
	if err != nil {
		return "", ErrDenied
	}
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", ErrStore
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	subject := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	code, digest, err := newRecovery()
	if err != nil {
		return "", err
	}
	_, err = n.accounts.InsertOne(ctx, bson.D{
		{Key: "_id", Value: subject}, {Key: "environment", Value: "staging"},
		{Key: "source", Value: nativeSource}, {Key: "alias_key", Value: name},
		{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false},
		{Key: "role", Value: roles.SelfRegistrationRole()},
		{Key: "credential_hash", Value: hash}, {Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)}, {Key: "recovery_digest", Value: digest},
		{Key: "created_at", Value: time.Now().UTC()},
	})
	if mongo.IsDuplicateKeyError(err) {
		return "", ErrNameUnavailable
	}
	if err != nil {
		return "", ErrStore
	}
	return code, nil
}

func nativeFilter(name string) bson.D {
	return bson.D{{Key: "environment", Value: "staging"}, {Key: "source", Value: nativeSource},
		{Key: "alias_key", Value: name}, {Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false}}
}

func (n *NativeAccounts) Login(ctx context.Context, input, candidate string) (string, error) {
	name, valid := centralName(input)
	if !n.ready(ctx) || !valid || len(candidate) == 0 || len(candidate) > 4096 {
		return "", ErrDenied
	}
	var row struct {
		Subject string `bson:"_id"`
	}
	if err := n.accounts.FindOne(ctx, nativeFilter(name)).Decode(&row); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	return n.issuer.Issue(ctx, row.Subject, candidate)
}

// Recover consumes the current 256-bit backup code, rotates it, replaces the
// password and revokes EVERY browser in one snapshot/majority transaction.
// A lost code requires a separate ownership process; there is no name-based
// reset or administrator/legacy account activation through this API.
func (n *NativeAccounts) Recover(ctx context.Context, input, code, candidate string) (string, error) {
	name, valid := centralName(input)
	digest, validCode := recoveryDigest(code)
	if !n.ready(ctx) || !valid || !validCode || !validNewPassword(candidate) {
		return "", ErrDenied
	}
	hash, err := password.HashNew(candidate)
	if err != nil {
		return "", ErrDenied
	}
	nextCode, nextDigest, err := newRecovery()
	if err != nil {
		return "", err
	}
	sess, err := n.issuer.client.StartSession()
	if err != nil {
		return "", ErrStore
	}
	defer sess.EndSession(context.Background())
	txn := options.Transaction().SetReadConcern(readconcern.Snapshot()).
		SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
	_, err = sess.WithTransaction(ctx, func(tx context.Context) (any, error) {
		filter := append(nativeFilter(name), bson.E{Key: "recovery_digest", Value: digest})
		var row struct {
			Subject    string `bson:"_id"`
			Credential int64  `bson:"credential_version"`
			Session    int64  `bson:"session_version"`
		}
		if err := n.accounts.FindOne(tx, filter).Decode(&row); err != nil {
			return nil, err
		}
		if !uuidV4.MatchString(row.Subject) || row.Credential < 1 || row.Session < 1 || row.Credential == math.MaxInt64 || row.Session == math.MaxInt64 {
			return nil, ErrDenied
		}
		filter = append(filter, bson.E{Key: "_id", Value: row.Subject}, bson.E{Key: "credential_version", Value: row.Credential}, bson.E{Key: "session_version", Value: row.Session})
		result, err := n.accounts.UpdateOne(tx, filter, bson.D{
			{Key: "$set", Value: bson.D{{Key: "credential_hash", Value: hash}, {Key: "recovery_digest", Value: nextDigest}}},
			{Key: "$inc", Value: bson.D{{Key: "credential_version", Value: int64(1)}, {Key: "session_version", Value: int64(1)}}},
		})
		if err != nil {
			return nil, err
		}
		if result.ModifiedCount != 1 {
			return nil, ErrDenied
		}
		if n.issuer.afterFence != nil {
			if err := n.issuer.afterFence(); err != nil {
				return nil, err
			}
		}
		return nil, n.issuer.sessions.DeleteSubject(tx, "staging", row.Subject)
	}, txn)
	if err != nil {
		if errors.Is(err, ErrDenied) || errors.Is(err, mongo.ErrNoDocuments) {
			return "", ErrDenied
		}
		return "", ErrStore
	}
	return nextCode, nil
}
