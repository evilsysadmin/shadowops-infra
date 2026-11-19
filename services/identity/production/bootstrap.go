// Package production defines an isolated, deliberately UNREADY TLS bootstrap.
//
// It is not an Identity provider: no login, user database connection, tokens,
// issuance or freshness API is wired. The production runtime must fail closed
// until those independent services have been audited and explicitly enabled.
package production

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/core"
)

const (
	Host     = "id.shadowops.dpdns.org"
	Database = "shadowops_identity_production"
	Audience = "bridgesquad"
	Origin   = "https://bridgesquad.shadowops.dpdns.org"
)

var ErrDenied = errors.New("production Identity bootstrap denied")

// Bundle is a private, environment-specific and non-publicly sourced contract.
// Only the Bridge Squad consumer is admitted in the initial production scope.
// The bootstrap deliberately does not consume the Mongo URI or consumer proof
// to make authentication decisions; there is no active authentication here.
type Bundle struct {
	Environment   string            `json:"environment"`
	MongoURI      string            `json:"mongo_uri"`
	MongoCA       string            `json:"mongo_ca_pem"`
	SigningSeed   string            `json:"signing_seed"`
	TLSCert       string            `json:"tls_certificate_pem"`
	TLSKey        string            `json:"tls_private_key_pem"`
	Consumers     map[string]string `json:"consumers"`
}

// LoadBundle rejects world/group-readable files, symlinks, unknown fields,
// trailing JSON, staging identifiers and insecure transport properties.
// Production bundle values must be supplied from independent protected custody.
func LoadBundle(path string) (Bundle, tls.Certificate, error) {
	bad := func() (Bundle, tls.Certificate, error) {
		return Bundle{}, tls.Certificate{}, ErrDenied
	}
	if !filepath.IsAbs(path) {
		return bad()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() < 1 || info.Size() > 131072 {
		return bad()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return bad()
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var b Bundle
	if decoder.Decode(&b) != nil {
		return bad()
	}
	var more any
	if decoder.Decode(&more) != io.EOF {
		return bad()
	}
	cert, err := b.Validate(time.Now().UTC())
	if err != nil {
		return bad()
	}
	return b, cert, nil
}

// Validate is offline and performs no DNS, Mongo or Cloudflare operations.
// A successful validation is NOT permission to serve user credentials.
func (b Bundle) Validate(now time.Time) (tls.Certificate, error) {
	deny := func() (tls.Certificate, error) { return tls.Certificate{}, ErrDenied }
	if b.Environment != "production" || len(b.Consumers) != 1 {
		return deny()
	}
	cred, ok := b.Consumers[Audience]
	if !ok || len(cred) != 48 || !strings.HasPrefix(cred, "soc1_") {
		return deny()
	}
	proof, err := base64.RawURLEncoding.DecodeString(cred[5:])
	if err != nil || len(proof) != 32 || base64.RawURLEncoding.EncodeToString(proof) != cred[5:] {
		return deny()
	}
	seed, err := base64.RawURLEncoding.DecodeString(b.SigningSeed)
	if err != nil || len(seed) != ed25519.SeedSize ||
		base64.RawURLEncoding.EncodeToString(seed) != b.SigningSeed ||
		bytes.Equal(seed, proof) {
		return deny()
	}
	id, err := core.New("production", seed)
	if err != nil || id.Issuer() != "https://"+Host {
		return deny()
	}
	uri, err := url.Parse(b.MongoURI)
	if err != nil || (uri.Scheme != "mongodb" && uri.Scheme != "mongodb+srv") ||
		uri.Host == "" || uri.User == nil || uri.User.Username() == "" ||
		uri.Path != "/"+Database || uri.Fragment != "" || uri.RawFragment != "" {
		return deny()
	}
	password, hasPassword := uri.User.Password()
	if !hasPassword || password == "" {
		return deny()
	}
	query := uri.Query()
	for key, vals := range query {
		switch strings.ToLower(key) {
		case "tls", "ssl":
			if len(vals) != 1 || vals[0] != "true" {
				return deny()
			}
		case "tlsinsecure", "tlsallowinvalidcertificates", "tlsallowinvalidhostnames",
			"tlsdisableocspendpointcheck", "tlsdisablecertificaterevocationcheck",:
			return deny()
		}
	}
	if query.Get("tls") != "true" && query.Get("ssl") != "true" {
		return deny()
	}
	if b.MongoCA == "" {
		return deny()
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.MongoCA)) {
		return deny()
	}
	cert, err := tls.X509KeyPair([]byte(b.TLSCert), []byte(b.TLSKey))
	if err != nil || len(cert.Certificate) == 0 {
		return deny()
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != Host ||
		now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.IsCA {
		return deny()
	}
	if err := leaf.VerifyHostname(Host); err != nil {
		return deny()
	}
	if len(leaf.ExtKeyUsage) > 0 {
		server := false
		for _, usage := range leaf.ExtKeyUsage {
			server = server || usage == x509.ExtKeyUsageServerAuth
		}
		if !server {
			return deny()
		}
	}
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok &&
		bytes.Equal(pub, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		return deny()
	}
	return cert, nil
}

// UnreadyHandler never issues credentials, tokens or keys, regardless of path.
// Even a syntactically valid private production bundle is not a running IdP.
func UnreadyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.TLS == nil || r.Host != Host {
			http.Error(w, "production TLS host required", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/livez" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "bootstrap live; auth disabled\n")
			return
		}
		if r.URL.Path == "/readyz" || r.URL.Path == "/api/identity/jwks" ||
			r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/api/identity/") {
			http.Error(w, "production Identity not provisioned", http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	})
}

// NewUnreadyServer binds the validated TLS key but never publishes a login or
// production issuer until a separately reviewed production backend is wired.
func NewUnreadyServer(cert tls.Certificate) (*http.Server, error) {
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, ErrDenied
	}
	return &http.Server{
		Addr: ":9443", Handler: UnreadyHandler(),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8 << 10,
	}, nil
}
