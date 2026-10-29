package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }
func get(t *testing.T, env string, s []byte) *Core {
	t.Helper()
	c, err := New(env, s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestRejectsUnknownEnvironmentAndInvalidSeed(t *testing.T) {
	for _, env := range []string{"", " ", "prod", "STAGING", "stage", "development", "local", "production ", "ci"} {
		if _, err := New(env, seed(1)); err == nil {
			t.Errorf("accepted environment %q", env)
		}
	}
	for _, s := range [][]byte{nil, {}, seed(1)[:31], append(seed(1), byte(1))} {
		if _, err := New("staging", s); err == nil {
			t.Errorf("accepted seed length %d", len(s))
		}
	}
}
func TestStagingAndProductionRequireDifferentActualKeys(t *testing.T) {
	stage := get(t, "staging", seed(1))
	prod := get(t, "production", seed(2))
	if stage.Issuer() != "https://id-staging.shadowops.dpdns.org" || prod.Issuer() != "https://id.shadowops.dpdns.org" {
		t.Fatal("wrong environment issuer")
	}
	if err := ValidateSeparation(stage, prod); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*Core{{stage, get(t, "production", seed(1))}, {prod, stage}, {stage, stage}, {nil, prod}} {
		if err := ValidateSeparation(pair[0], pair[1]); err == nil {
			t.Fatal("unsafe identity pair accepted")
		}
	}
}
func TestJWKSIsOnlyPublicEd25519Key(t *testing.T) {
	c := get(t, "staging", seed(3))
	raw, err := c.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"d"`)) || bytes.Contains(raw, seed(3)) {
		t.Fatal("private material in JWKS")
	}
	var set KeySet
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 {
		t.Fatal("malformed JWKS", err)
	}
	k := set.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Use != "sig" || k.Alg != "EdDSA" || !strings.HasPrefix(k.Kid, "identity-") || len(k.Kid) != 25 {
		t.Fatal("wrong JWKS fields")
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(pub) != 32 || !bytes.Equal(pub, c.public) {
		t.Fatal("wrong public key")
	}
}
func TestProbeNeverIssuesAUserOrProductAudienceAndRejectsCrossEnvironment(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stage := get(t, "staging", seed(1))
	prod := get(t, "production", seed(2))
	token, err := stage.ProbeToken(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.VerifyProbe(token, now); err != nil {
		t.Fatal(err)
	}
	if err := prod.VerifyProbe(token, now); err == nil {
		t.Fatal("staging token verified by production")
	}
	for _, at := range []time.Time{now.Add(3 * time.Minute), now.Add(-2 * time.Minute)} {
		if stage.VerifyProbe(token, at) == nil {
			t.Fatal("expired or not-yet-valid token accepted")
		}
	}
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload probeClaims
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Aud != "shadowops-identity-probe" || !strings.HasPrefix(payload.Sub, "probe:") {
		t.Fatal("probe confused with a user")
	}
	for _, bad := range []string{"", "a.b", token + "junk", parts[0] + "." + parts[1] + "." + strings.Repeat("A", 85)} {
		if stage.VerifyProbe(bad, now) == nil {
			t.Fatal("invalid token accepted")
		}
	}
}
func TestTokenSignerOwnsIndependentKeyMaterial(t *testing.T) {
	original := seed(2)
	c := get(t, "staging", original)
	original[0] = 0
	token, err := c.ProbeToken(time.Unix(1800000000, 0))
	if err != nil || c.VerifyProbe(token, time.Unix(1800000000, 0)) != nil {
		t.Fatal("external seed mutated key")
	}
}
