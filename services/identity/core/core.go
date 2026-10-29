// Package core is the isolated signing foundation for future ShadowOps Identity.
// It deliberately issues only synthetic, non-user probe JWTs: no login,
// password verification, account store, app token issuance, or HTTP server.
package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ProbeAudience = "shadowops-identity-probe"
	probeLifetime = 2 * time.Minute
)

var ErrInvalid = errors.New("invalid ShadowOps Identity probe")

type Core struct {
	env    string
	issuer string
	key    ed25519.PrivateKey
	public ed25519.PublicKey
	kid    string
}

type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type KeySet struct {
	Keys []Key `json:"keys"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type probeClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// New has no environment default. A production issuer cannot be built by a
// misspelled staging configuration (or vice versa). The seed is provided by
// the caller, never generated or derived from Chess Studio's JWT_SECRET.
func New(environment string, seed []byte) (*Core, error) {
	var issuer string
	switch environment {
	case "staging":
		issuer = "https://id-staging.shadowops.dpdns.org"
	case "production":
		issuer = "https://id.shadowops.dpdns.org"
	default:
		return nil, fmt.Errorf("%w: explicit staging or production environment required", ErrInvalid)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: Ed25519 seed must be exactly 32 bytes", ErrInvalid)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	return &Core{env: environment, issuer: issuer, key: key, public: public, kid: "identity-" + hex.EncodeToString(digest[:8])}, nil
}

func (c *Core) Environment() string { return c.env }
func (c *Core) Issuer() string      { return c.issuer }

// ValidateSeparation checks two *actual* in-memory instances. Merely setting
// different issuer names does not guarantee signing keys are independent.
func ValidateSeparation(staging, production *Core) error {
	if staging == nil || production == nil || staging.env != "staging" || production.env != "production" || ed25519.PublicKey(staging.public).Equal(production.public) {
		return fmt.Errorf("%w: staging and production must use distinct issuers and keys", ErrInvalid)
	}
	return nil
}

// JWKS publishes public verification material only, with no private seed.
func (c *Core) JWKS() ([]byte, error) {
	if c == nil {
		return nil, ErrInvalid
	}
	return json.Marshal(KeySet{Keys: []Key{{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: "EdDSA", Kid: c.kid, X: base64.RawURLEncoding.EncodeToString(c.public)}}})
}

// ProbeToken cannot accept an account ID or audience. No current product
// trusts its synthetic audience; never expose it as a login/token endpoint.
func (c *Core) ProbeToken(now time.Time) (string, error) {
	if c == nil || now.IsZero() {
		return "", ErrInvalid
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("%w: cannot generate probe identifier", ErrInvalid)
	}
	claims := probeClaims{Iss: c.issuer, Aud: ProbeAudience, Sub: "probe:" + hex.EncodeToString(nonce), Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(probeLifetime).Unix(), Jti: hex.EncodeToString(nonce)}
	headerBytes, err := json.Marshal(header{Alg: "EdDSA", Typ: "JWT", Kid: c.kid})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	message := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sig := ed25519.Sign(c.key, []byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyProbe is *only* a self-test; it cannot verify application auth tokens.
func (c *Core) VerifyProbe(token string, now time.Time) error {
	if c == nil || now.IsZero() || len(token) > 4096 {
		return ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalid
	}
	decode := func(encoded string, max int) ([]byte, error) {
		if len(encoded) == 0 || len(encoded) > 2*max {
			return nil, ErrInvalid
		}
		b, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != encoded {
			return nil, ErrInvalid
		}
		return b, nil
	}
	hb, err := decode(parts[0], 512)
	if err != nil {
		return err
	}
	cb, err := decode(parts[1], 1024)
	if err != nil {
		return err
	}
	signature, err := decode(parts[2], 64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	if !ed25519.Verify(c.public, []byte(parts[0]+"."+parts[1]), signature) {
		return ErrInvalid
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "EdDSA" || h.Typ != "JWT" || h.Kid != c.kid {
		return ErrInvalid
	}
	var p probeClaims
	if err := json.Unmarshal(cb, &p); err != nil {
		return ErrInvalid
	}
	current := now.Unix()
	if p.Iss != c.issuer || p.Aud != ProbeAudience || !strings.HasPrefix(p.Sub, "probe:") || len(p.Sub) != 38 || p.Jti != strings.TrimPrefix(p.Sub, "probe:") || len(p.Jti) != 32 || p.Iat <= 0 || p.Iat > current+30 || p.Nbf > current+30 || p.Nbf < p.Iat || p.Exp <= current || p.Exp <= p.Iat || p.Exp-p.Iat > int64(probeLifetime.Seconds()) {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(p.Jti); err != nil {
		return ErrInvalid
	}
	return nil
}
