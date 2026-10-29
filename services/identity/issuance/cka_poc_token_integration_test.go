package issuance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/revocation"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func testCKASigner(t *testing.T, issuer *Issuer) *CKAPoCSigner {
	t.Helper()
	s, err := NewCKAPoCSigner(issuer, bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testClaims(t *testing.T, signed string, jwks []byte) ckaPOCClaims {
	t.Helper()
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatal("expected JWT")
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil || len(set.Keys) != 1 {
		t.Fatal("missing public JWKS", err)
	}
	encodedHead, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil { t.Fatal(err) }
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(encodedHead, &header); err != nil ||
		header.Alg != "EdDSA" || header.Typ != "JWT" || header.Kid != set.Keys[0].Kid {
		t.Fatal("unexpected JWT header", err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	if err != nil { t.Fatal(err) }
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signed JWT does not verify using public Identity JWKS", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { t.Fatal(err) }
	var claims ckaPOCClaims
	if err := json.Unmarshal(body, &claims); err != nil { t.Fatal(err) }
	return claims
}

func TestCKATokenOnlyForMajorityCommittedVersionedSession(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	issuer, err := NewStagingIssuer(ctx, client)
	if err != nil { t.Fatal(err) }
	signer := testCKASigner(t, issuer)
	jwks, err := signer.JWKS()
	if err != nil { t.Fatal(err) }
	if bytes.Contains(jwks, bytes.Repeat([]byte{0x77}, ed25519.SeedSize)) {
		t.Fatal("JWKS exposed private seed")
	}
	if value, err := signer.IssuePoCToken(ctx, "so1_not-a-session"); value != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("unsigned caller minted CKA JWT", err)
	}
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil { t.Fatal(err) }
	token, err := signer.IssuePoCToken(ctx, handle)
	if err != nil { t.Fatal("valid synthetic session rejected", err) }
	now := time.Now().UTC().Unix()
	claims := testClaims(t, token, jwks)
	if claims.Iss != "https://id-staging.shadowops.dpdns.org" ||
		claims.Aud != "cka-simulator" || claims.Sub != alice ||
		claims.Sv != 1 || claims.Exp <= now ||
		claims.Exp-claims.Iat > int64(ckaPoCTokenLifetime.Seconds()) ||
		claims.Exp-claims.Iat <= 0 || claims.Nbf != claims.Iat ||
		len(claims.Jti) == 0 {
		t.Fatal("invalid signed synthetic CKA session claims", claims)
	}
	if sessionCount(t, db) != 1 {
		t.Fatal("token signing unexpectedly changed session count")
	}
	revoker, err := revocation.NewStagingRevoker(client)
	if err != nil { t.Fatal(err) }
	if err := revoker.SuspendAndRevoke(ctx, alice, 1); err != nil { t.Fatal(err) }
	if signed, err := signer.IssuePoCToken(ctx, handle); signed != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("revoked account/session minted another CKA JWT", err)
	}
}

func TestCKATokenCannotUseOldRefreshedHandleAndRollsBack(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil { t.Fatal(err) }
	signer := testCKASigner(t, issuer)
	ctx := context.Background()
	handle, err := issuer.Issue(ctx, alice, secret)
	if err != nil { t.Fatal(err) }
	next, err := issuer.Refresh(ctx, handle)
	if err != nil { t.Fatal(err) }
	if signed, err := signer.IssuePoCToken(ctx, handle); signed != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("rotated stale handle minted CKA JWT", err)
	}
	before := struct { Fence int64 `bson:"login_fence"` }{}
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key:"_id",Value:alice}}).Decode(&before); err != nil { t.Fatal(err) }
	issuer.afterFence = func() error { return errors.New("synthetic post-fence failure") }
	if signed, err := signer.IssuePoCToken(ctx, next); signed != "" || !errors.Is(err, ErrStore) {
		t.Fatal("failed transaction returned token", err)
	}
	var after struct { Fence int64 `bson:"login_fence"` }
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.D{{Key:"_id",Value:alice}}).Decode(&after); err != nil { t.Fatal(err) }
	if before.Fence != after.Fence {
		t.Fatal("failed transaction committed account fence")
	}
	issuer.afterFence = nil
	if signed, err := signer.IssuePoCToken(ctx, next); signed == "" || err != nil {
		t.Fatal("committed refreshed session could not sign", err)
	}
}

func TestCKATokenStrictInputsFailClosed(t *testing.T) {
	if _, err := NewCKAPoCSigner(nil, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrDenied) {
		t.Fatal("nil issuer accepted")
	}
	if _, err := NewCKAPoCSigner(&Issuer{}, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, ErrDenied) {
		t.Fatal("uninitialized issuer accepted")
	}
	var absent *CKAPoCSigner
	if token, err := absent.IssuePoCToken(context.Background(), "x"); token != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("nil signer accepted")
	}
	if _, err := absent.JWKS(); !errors.Is(err, ErrDenied) {
		t.Fatal("nil signer published JWKS")
	}
	client, db := replica(t)
	syntheticActive(t, db)
	issuer, err := NewStagingIssuer(context.Background(), client)
	if err != nil { t.Fatal(err) }
	if _, err := NewCKAPoCSigner(issuer, []byte("too-short")); !errors.Is(err, ErrDenied) {
		t.Fatal("invalid private seed accepted")
	}
	signer := testCKASigner(t, issuer)
	handle, err := issuer.Issue(context.Background(), alice, secret)
	if err != nil { t.Fatal(err) }
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if token, err := signer.IssuePoCToken(c, handle); token != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("cancelled context signed token")
	}
	_, err = db.Collection("pending_accounts").UpdateOne(context.Background(),
		bson.D{{Key:"_id", Value:alice}},
		bson.D{{Key:"$inc", Value:bson.D{{Key:"session_version",Value:int64(1)}}}})
	if err != nil { t.Fatal(err) }
	if signed, err := signer.IssuePoCToken(context.Background(), handle); signed != "" || !errors.Is(err, ErrDenied) {
		t.Fatal("obsolete session version minted CKA token", err)
	}
}
