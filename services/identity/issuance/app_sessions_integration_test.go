package issuance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/revocation"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var sharedApplications = []Application{ChessStudio, Chronicles, CKASimulator}

func TestOneCentralSessionIssuesThreeAudienceBoundTokens(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x77}, ed25519.SeedSize)
	claims := make(map[Application]appTokenClaims)
	checkers := make(map[Application]*StagingAppFreshness)
	var centralJWKS []byte
	for _, app := range sharedApplications {
		signer, err := NewStagingAppSigner(issuer, seed, app)
		if err != nil {
			t.Fatal(err)
		}
		jwks, err := signer.JWKS()
		if err != nil {
			t.Fatal(err)
		}
		if centralJWKS == nil {
			centralJWKS = jwks
		} else if !bytes.Equal(jwks, centralJWKS) {
			t.Fatal("applications do not share central issuer key")
		}
		signed, err := signer.IssueToken(ctx, handle)
		if err != nil {
			t.Fatal(err)
		}
		claim := testClaims(t, signed, jwks) // Verifies the actual JWT signature with public JWKS.
		if claim.Sub != alice || claim.Iss != stagingIssuerURL || claim.Aud != string(app) || claim.Sv != 1 {
			t.Fatal("application created another identity or audience")
		}
		claims[app] = claim
		checker, err := NewStagingAppFreshness(issuer, app)
		if err != nil {
			t.Fatal(err)
		}
		checkers[app] = checker
	}
	// Full 3x3 audience isolation matrix: exactly three accepts and six denials.
	for _, consumer := range sharedApplications {
		for _, tokenApp := range sharedApplications {
			claim := claims[tokenApp]
			evidence, err := checkers[consumer].Check(ctx, claim.Sub, claim.Sv, claim.Jti)
			if consumer != tokenApp {
				if !errors.Is(err, ErrDenied) || evidence != (ApplicationFreshnessEvidence{}) {
					t.Fatalf("%s accepted %s token", consumer, tokenApp)
				}
			} else if err != nil || evidence.Audience != consumer || evidence.Subject != alice || !evidence.SessionActive {
				t.Fatal("matching audience denied", err)
			}
		}
	}
	for _, app := range sharedApplications {
		for _, other := range sharedApplications {
			if app != other && claims[app].Jti == claims[other].Jti {
				t.Fatal("application token identifiers reused")
			}
		}
	}
	if sessionCount(t, db) != 1 {
		t.Fatal("per-application token issuance created extra sessions")
	}
	if count, err := db.Collection("pending_accounts").CountDocuments(ctx, bson.D{}); err != nil || count != 1 {
		t.Fatal("application token issuance created extra accounts", err)
	}
	if count, err := db.Collection(appTokenCollection).CountDocuments(ctx, bson.D{}); err != nil || count != 3 {
		t.Fatal("not all three application bindings were registered", err)
	}
	// Central logout revokes ALL three application tokens, but no other browser.
	otherHandle, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, _ := NewStagingAppSigner(issuer, seed, ChessStudio)
	otherToken, err := otherSigner.IssueToken(ctx, otherHandle)
	if err != nil {
		t.Fatal(err)
	}
	otherClaim := testClaims(t, otherToken, centralJWKS)
	if err := issuer.Logout(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if err := issuer.Logout(ctx, handle); err != nil {
		t.Fatal("logout must be idempotent", err)
	}
	for _, app := range sharedApplications {
		claim := claims[app]
		if _, err := checkers[app].Check(ctx, claim.Sub, claim.Sv, claim.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("central logout left an app token active", app, err)
		}
	}
	if _, err := checkers[ChessStudio].Check(ctx, alice, otherClaim.Sv, otherClaim.Jti); err != nil {
		t.Fatal("logout incorrectly revoked another browser", err)
	}
}

func TestSharedSessionRefreshAndAccountSuspensionApplyToEveryApp(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x77}, ed25519.SeedSize)
	signers := make(map[Application]*StagingAppSigner)
	checkers := make(map[Application]*StagingAppFreshness)
	before := make(map[Application]appTokenClaims)
	for _, app := range sharedApplications {
		signer, err := NewStagingAppSigner(issuer, seed, app)
		if err != nil {
			t.Fatal(err)
		}
		checker, err := NewStagingAppFreshness(issuer, app)
		if err != nil {
			t.Fatal(err)
		}
		token, err := signer.IssueToken(ctx, handle)
		if err != nil {
			t.Fatal(err)
		}
		jwks, _ := signer.JWKS()
		before[app] = testClaims(t, token, jwks)
		signers[app] = signer
		checkers[app] = checker
	}
	refreshed, err := issuer.Refresh(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range sharedApplications {
		claim := before[app]
		if _, err := checkers[app].Check(ctx, alice, claim.Sv, claim.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("old source session accepted", app, err)
		}
		if _, err := signers[app].IssueToken(ctx, handle); !errors.Is(err, ErrDenied) {
			t.Fatal("rotated handle minted another app token", app, err)
		}
		token, err := signers[app].IssueToken(ctx, refreshed)
		if err != nil {
			t.Fatal(err)
		}
		jwks, _ := signers[app].JWKS()
		before[app] = testClaims(t, token, jwks)
		if _, err := checkers[app].Check(ctx, alice, before[app].Sv, before[app].Jti); err != nil {
			t.Fatal(err)
		}
	}
	revoker, err := revocation.NewStagingRevoker(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoker.SuspendAndRevoke(ctx, alice, 1); err != nil {
		t.Fatal(err)
	}
	for _, app := range sharedApplications {
		claim := before[app]
		if _, err := checkers[app].Check(ctx, alice, claim.Sv, claim.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("revoked account accepted", app, err)
		}
		if _, err := signers[app].IssueToken(ctx, refreshed); !errors.Is(err, ErrDenied) {
			t.Fatal("revoked account minted app token", app, err)
		}
	}
}

func TestCKACompatibilityKeepsItsEvidenceShapeAndRegisteredTokens(t *testing.T) {
	issuer, signer, checker, _, handle, _ := freshnessFixture(t)
	ctx := context.Background()
	token, err := signer.IssuePoCToken(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := signer.JWKS()
	claim := testClaims(t, token, jwks)
	generic, err := NewStagingAppFreshness(issuer, CKASimulator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generic.Check(ctx, alice, claim.Sv, claim.Jti); err != nil {
		t.Fatal("original CKA signer binding rejected", err)
	}
	appSigner, err := NewStagingAppSigner(issuer, bytes.Repeat([]byte{0x77}, ed25519.SeedSize), CKASimulator)
	if err != nil {
		t.Fatal(err)
	}
	token, err = appSigner.IssueToken(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	claim = testClaims(t, token, jwks)
	evidence, err := checker.Check(ctx, alice, claim.Sv, claim.Jti)
	if err != nil {
		t.Fatal("original CKA checker rejected common signer", err)
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	if len(shape) != 8 || shape["audience"] != nil {
		t.Fatal("legacy CKA evidence shape changed")
	}
}

func TestApplicationConfigurationAndLogoutRejectInvalidInput(t *testing.T) {
	for _, app := range []Application{"", "CKA", "production", "chess-studio ", "unknown"} {
		if app.valid() {
			t.Fatal("unknown app registered")
		}
		if _, err := NewStagingAppSigner(nil, nil, app); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid signer accepted")
		}
		if _, err := NewStagingAppFreshness(nil, app); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid checker accepted")
		}
	}
	var absent *Issuer
	if err := absent.Logout(context.Background(), "x"); !errors.Is(err, ErrDenied) {
		t.Fatal("nil issuer logout accepted")
	}
	var signer *StagingAppSigner
	if token, err := signer.IssueToken(context.Background(), "x"); token != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("nil signer accepted")
	}
	var checker *StagingAppFreshness
	if _, err := checker.Check(context.Background(), alice, 1, "x"); !errors.Is(err, ErrDenied) {
		t.Fatal("nil checker accepted")
	}
}

func TestConfiguredServiceCannotSelectUnregisteredAudience(t *testing.T) {
	client, _ := replica(t)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x77}, ed25519.SeedSize)
	for _, app := range []Application{"", "CKA", "production", "chess-studio ", "unknown"} {
		if _, err := NewStagingAppSigner(issuer, seed, app); !errors.Is(err, ErrDenied) {
			t.Fatal("unregistered audience accepted by configured signer", app, err)
		}
		if _, err := NewStagingAppFreshness(issuer, app); !errors.Is(err, ErrDenied) {
			t.Fatal("unregistered audience accepted by configured checker", app, err)
		}
	}
	if err := issuer.Logout(nil, "x"); !errors.Is(err, ErrDenied) {
		t.Fatal("nil logout context accepted")
	}
	if err := issuer.Logout(context.Background(), "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("malformed logout handle accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := issuer.Logout(ctx, "x"); !errors.Is(err, ErrDenied) {
		t.Fatal("cancelled logout accepted")
	}
}
