package issuance

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/revocation"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func freshnessFixture(t *testing.T) (*Issuer, *CKAPoCSigner, *StagingCKAFreshness, *mongo.Database, string, ckaPOCClaims) {
	t.Helper()
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	signer := testCKASigner(t, issuer)
	checker, err := NewStagingCKAFreshness(issuer)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := issuer.Issue(context.Background(), alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.IssuePoCToken(context.Background(), handle)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	return issuer, signer, checker, db, handle, testClaims(t, token, jwks)
}

func TestFreshnessCommittedBindingCheckedOnEveryAttempt(t *testing.T) {
	_, _, checker, db, handle, claims := freshnessFixture(t)
	ctx := context.Background()
	for attempt := 0; attempt < 2; attempt++ {
		evidence, err := checker.Check(ctx, alice, claims.Sv, claims.Jti)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Issuer != claims.Iss || evidence.Subject != alice || evidence.SessionVersion != claims.Sv || evidence.TokenJTI != claims.Jti ||
			!evidence.AccountActive || !evidence.SessionActive || !evidence.TokenActive || time.Now().Unix()-evidence.CheckedAt > 2 {
			t.Fatal("incorrect bound freshness evidence")
		}
	}
	var record struct {
		Fence int64 `bson:"freshness_fence"`
	}
	raw := db.Collection(appTokenCollection).FindOne(ctx, bson.D{{Key: "_id", Value: tokenDigest(claims.Jti)}})
	if err := raw.Decode(&record); err != nil || record.Fence != 2 {
		t.Fatal("checker cached instead of checking each attempt", err)
	}
	data, err := raw.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(handle)) || bytes.Contains(data, []byte(claims.Jti)) {
		t.Fatal("raw handle or JTI persisted")
	}
}

func TestFreshnessRejectsJWTAfterRealAccountRevocation(t *testing.T) {
	issuer, signer, checker, _, handle, claims := freshnessFixture(t)
	ctx := context.Background()
	token, err := signer.IssuePoCToken(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := signer.JWKS()
	claims = testClaims(t, token, jwks)
	if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); err != nil {
		t.Fatal(err)
	}
	revoker, err := revocation.NewStagingRevoker(issuer.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.SuspendAndRevoke(ctx, alice, 1); err != nil {
		t.Fatal(err)
	}
	// The original token STILL has a mathematically valid Ed25519 signature.
	testClaims(t, token, jwks)
	if evidence, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); !errors.Is(err, ErrDenied) || evidence.AccountActive {
		t.Fatal("valid signature bypassed completed revocation", err)
	}
}

func TestFreshnessRejectsRotatedAndDeletedSourceSession(t *testing.T) {
	issuer, signer, checker, db, handle, old := freshnessFixture(t)
	ctx := context.Background()
	next, err := issuer.Refresh(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.Check(ctx, alice, old.Sv, old.Jti); !errors.Is(err, ErrDenied) {
		t.Fatal("rotated token still active", err)
	}
	token, err := signer.IssuePoCToken(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := signer.JWKS()
	claims := testClaims(t, token, jwks)
	if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); err != nil {
		t.Fatal(err)
	}
	digest, _ := stagingHandleDigest(next)
	// Exercise deletion of the exact source session (logout semantics).
	if err := issuer.sessions.Delete(ctx, "staging", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); !errors.Is(err, ErrDenied) {
		t.Fatal("deleted session remained active", err)
	}
	count, err := db.Collection(appTokenCollection).CountDocuments(ctx, bson.D{})
	if err != nil || count != 2 {
		t.Fatal("fixture did not retain tokens independently of session deletion", err)
	}
}

func TestFreshnessUnknownOrMismatchedClaimsAndInactiveToken(t *testing.T) {
	_, _, checker, db, _, claims := freshnessFixture(t)
	ctx := context.Background()
	for _, input := range []struct {
		sub string
		sv  int64
		jti string
	}{
		{"22222222-2222-4222-8222-222222222222", claims.Sv, claims.Jti},
		{alice, claims.Sv + 1, claims.Jti},
		{alice, claims.Sv, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))},
	} {
		if _, err := checker.Check(ctx, input.sub, input.sv, input.jti); !errors.Is(err, ErrDenied) {
			t.Fatal("unbound claim accepted", err)
		}
	}
	for _, patch := range []bson.D{
		{{Key: "active", Value: false}},
		{{Key: "active", Value: true}, {Key: "audience", Value: "chess-studio"}},
		{{Key: "audience", Value: ckaAudience}, {Key: "issuer", Value: "https://id.shadowops.dpdns.org"}},
		{{Key: "issuer", Value: stagingIssuerURL}, {Key: "session_digest", Value: "bad"}},
	} {
		if _, err := db.Collection(appTokenCollection).UpdateOne(ctx, bson.D{{Key: "_id", Value: tokenDigest(claims.Jti)}}, bson.D{{Key: "$set", Value: patch}}); err != nil {
			t.Fatal(err)
		}
		if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("inactive or malformed token accepted", err)
		}
	}
}

func TestFreshnessExpiresWithoutRelyingOnTTLDeletion(t *testing.T) {
	_, _, checker, db, _, claims := freshnessFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, err := db.Collection(appTokenCollection).UpdateOne(ctx, bson.D{{Key: "_id", Value: tokenDigest(claims.Jti)}}, bson.D{{Key: "$set", Value: bson.D{
		{Key: "issued_at", Value: now.Add(-2 * time.Minute)}, {Key: "expires_at", Value: now.Add(-time.Second)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); !errors.Is(err, ErrDenied) {
		t.Fatal("retained expired registry row accepted", err)
	}
}

func TestTokenRegistryFailureRollsBackIssuance(t *testing.T) {
	issuer, signer, _, db, handle, _ := freshnessFixture(t)
	ctx := context.Background()
	if err := db.Collection(appTokenCollection).Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCollection(ctx, appTokenCollection, options.CreateCollection().SetValidator(bson.D{{Key: "forbidden", Value: true}})); err != nil {
		t.Fatal(err)
	}
	var before, after struct {
		Fence int64 `bson:"login_fence"`
	}
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: alice}}).Decode(&before); err != nil {
		t.Fatal(err)
	}
	if token, err := signer.IssuePoCToken(ctx, handle); token != "" || !errors.Is(err, ErrStore) {
		t.Fatal("registry failure returned JWT", err)
	}
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: alice}}).Decode(&after); err != nil {
		t.Fatal(err)
	}
	if before.Fence != after.Fence {
		t.Fatal("failed registry transaction committed account fence")
	}
	if count, err := db.Collection(appTokenCollection).CountDocuments(ctx, bson.D{}); err != nil || count != 0 {
		t.Fatal("failed registry insert committed", err)
	}
	if sessionCount(t, db) != 1 || issuer.client == nil {
		t.Fatal("failed mint changed source session")
	}
}

func TestFreshnessChecksRacingRevocationNeverOutliveItsCommit(t *testing.T) {
	issuer, _, checker, _, _, claims := freshnessFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, _ = checker.Check(ctx, alice, claims.Sv, claims.Jti) }()
	}
	close(start)
	revoker, err := revocation.NewStagingRevoker(issuer.client)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.SuspendAndRevoke(ctx, alice, 1); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for n := 0; n < 3; n++ {
		if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("post-revocation check succeeded", err)
		}
	}
}

func TestFreshnessUninitializedAndMalformedInput(t *testing.T) {
	if _, err := NewStagingCKAFreshness(nil); !errors.Is(err, ErrDenied) {
		t.Fatal("nil issuer accepted")
	}
	var absent *StagingCKAFreshness
	if _, err := absent.Check(context.Background(), alice, 1, "x"); !errors.Is(err, ErrDenied) {
		t.Fatal("nil checker accepted")
	}
	_, _, checker, _, _, claims := freshnessFixture(t)
	for _, jti := range []string{"", "?", claims.Jti + "=", string(bytes.Repeat([]byte{'x'}, 4096))} {
		if _, err := checker.Check(context.Background(), alice, 1, jti); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid JTI accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checker.Check(ctx, alice, 1, claims.Jti); !errors.Is(err, ErrDenied) {
		t.Fatal("cancelled request accepted")
	}
}

func TestFreshnessUnavailableAuthorityProducesNoEvidence(t *testing.T) {
	issuer, _, checker, _, _, claims := freshnessFixture(t)
	ctx := context.Background()
	if _, err := checker.Check(ctx, alice, claims.Sv, claims.Jti); err != nil {
		t.Fatal(err)
	}
	if err := issuer.client.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	evidence, err := checker.Check(ctx, alice, claims.Sv, claims.Jti)
	if !errors.Is(err, ErrStore) || evidence != (SessionFreshnessEvidence{}) {
		t.Fatal("unavailable authority returned evidence", err)
	}
}
