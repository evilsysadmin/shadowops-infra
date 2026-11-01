package runtime

import (
	"bytes"
	"context"
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

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"github.com/evilsysadmin/shadowops-infra/services/identity/websession"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const ServiceAddress = ":9443"
const serviceHost = "id-staging.shadowops.dpdns.org"
const serviceDatabase = "shadowops_identity_staging"

// BuildSHA is stamped by the trusted image builder; it contains no secret.
var BuildSHA = "development"

var ErrServiceUnavailable = errors.New("staging Identity service unavailable")

// ServiceConfig is a single private, operator-provisioned staging bundle.
// No private value is accepted from an HTTP request or emitted by diagnostics.
type ServiceConfig struct {
	Environment    string                         `json:"environment"`
	MongoURI       string                         `json:"mongo_uri"`
	MongoCA        string                         `json:"mongo_ca_pem"`
	SigningSeed    string                         `json:"signing_seed"`
	TLSCertificate string                         `json:"tls_certificate_pem"`
	TLSPrivateKey  string                         `json:"tls_private_key_pem"`
	Consumers      websession.ConsumerCredentials `json:"consumers"`
	AdminAliasCredential string `json:"chronicles_admin_alias_credential,omitempty"`
}

func LoadServiceConfig(filename string) (ServiceConfig, error) {
	if !filepath.IsAbs(filename) {
		return ServiceConfig{}, ErrUnsafeConfiguration
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 131072 {
		return ServiceConfig{}, ErrUnsafeConfiguration
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return ServiceConfig{}, ErrUnsafeConfiguration
	}
	defer clear(data)
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var cfg ServiceConfig
	if d.Decode(&cfg) != nil {
		return ServiceConfig{}, ErrUnsafeConfiguration
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ServiceConfig{}, ErrUnsafeConfiguration
	}
	if _, _, _, err := cfg.validate(time.Now()); err != nil {
		return ServiceConfig{}, err
	}
	return cfg, nil
}

func (cfg ServiceConfig) validate(now time.Time) ([]byte, tls.Certificate, *tls.Config, error) {
	bad := func() ([]byte, tls.Certificate, *tls.Config, error) {
		return nil, tls.Certificate{}, nil, ErrUnsafeConfiguration
	}
	if cfg.Environment != "staging" || len(cfg.Consumers) == 0 || len(cfg.Consumers) > 3 {
		return bad()
	}
	seed, err := base64.RawURLEncoding.DecodeString(cfg.SigningSeed)
	if err != nil || len(seed) != 32 || base64.RawURLEncoding.EncodeToString(seed) != cfg.SigningSeed {
		return bad()
	}
	if cfg.AdminAliasCredential != "" {
		if _, valid := adminAliasCredentialDigest(cfg.AdminAliasCredential); !valid { return bad() }
	}
	for app, key := range cfg.Consumers {
		if app != issuance.ChessStudio && app != issuance.Chronicles && app != issuance.CKASimulator {
			return bad()
		}
		if len(key) != 48 || !strings.HasPrefix(key, "soc1_") {
			return bad()
		}
		raw, err := base64.RawURLEncoding.DecodeString(key[5:])
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != key[5:] {
			return bad()
		}
	}
	u, err := url.Parse(cfg.MongoURI)
	if err != nil || (u.Scheme != "mongodb" && u.Scheme != "mongodb+srv") || u.Host == "" || u.User == nil {
		return bad()
	}
	if u.Path != "" && u.Path != "/" && u.Path != "/"+serviceDatabase {
		return bad()
	}
	for key, values := range u.Query() {
		switch strings.ToLower(key) {
		case "tls", "ssl":
			if len(values) != 1 || values[0] != "true" {
				return bad()
			}
		case "tlsinsecure", "tlsallowinvalidcertificates", "tlsallowinvalidhostnames", "tlsdisableocspendpointcheck":
			return bad()
		}
	}
	certificate, err := tls.X509KeyPair([]byte(cfg.TLSCertificate), []byte(cfg.TLSPrivateKey))
	if err != nil || len(certificate.Certificate) == 0 {
		return bad()
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != serviceHost || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return bad()
	}
	if key, ok := leaf.PublicKey.(ed25519.PublicKey); ok && bytes.Equal(key, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		return bad()
	}
	var roots *x509.CertPool
	if cfg.MongoCA != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.MongoCA)) {
			return bad()
		}
	}
	return seed, certificate, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

type RunningService struct {
	Server      *http.Server
	Client      *mongo.Client
	Certificate tls.Certificate
}

// NewStagingService refuses unauthenticated/admin Mongo clients and requires
// a writable replica set before wiring any account/login route. The operator
// must provision the exact three-collection application role separately.
func NewStagingService(ctx context.Context, cfg ServiceConfig) (*RunningService, error) {
	seed, certificate, mongoTLS, err := cfg.validate(time.Now())
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnsafeConfiguration
	}
	client, err := mongo.Connect(options.Client().ApplyURI(cfg.MongoURI).SetTLSConfig(mongoTLS).SetServerSelectionTimeout(3 * time.Second).SetConnectTimeout(3 * time.Second))
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	failed := true
	defer func() {
		if failed {
			_ = client.Disconnect(context.Background())
		}
	}()
	if err := verifyRuntimeRole(ctx, client); err != nil {
		return nil, err
	}
	if err := serviceReady(ctx, client); err != nil {
		return nil, ErrServiceUnavailable
	}
	issuer, err := issuance.NewStagingIssuer(ctx, client)
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	_, err = client.Database(serviceDatabase).Collection("staging_cka_tokens").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetName("token_expiry_ttl").SetExpireAfterSeconds(0)})
	if err != nil {
		return nil, ErrServiceUnavailable
	}
	h, err := websession.NewStagingServiceHandler(ctx, issuer, seed, cfg.Consumers)
	if err != nil {
		return nil, ErrUnsafeConfiguration
	}
	var aliases *adminAliasHandler
	if cfg.AdminAliasCredential != "" {
		aliases, err = newAdminAliasHandler(cfg.AdminAliasCredential,
			adminAliasesFromMongo(client.Database(serviceDatabase).Collection("pending_accounts")))
		if err != nil { return nil, ErrUnsafeConfiguration }
	}
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == AdminAliasesPath && aliases != nil {
			aliases.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/livez" && r.URL.Path != "/readyz" && r.URL.Path != "/api/identity/release" {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil || r.Host != serviceHost {
			http.Error(w, "staging TLS host required", 403)
			return
		}
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method denied", 405)
			return
		}
		if r.URL.Path == "/api/identity/release" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"service": "shadowops-identity", "environment": "staging", "source_sha": BuildSHA})
			return
		}
		if r.URL.Path == "/readyz" {
			probe, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if serviceReady(probe, client) != nil {
				http.Error(w, "identity unavailable", 503)
				return
			}
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok\n")
	})
	server := &http.Server{Addr: ServiceAddress, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	failed = false
	return &RunningService{Server: server, Client: client, Certificate: certificate}, nil
}

func serviceReady(ctx context.Context, client *mongo.Client) error {
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return ErrServiceUnavailable
	}
	var hello struct {
		SetName string `bson:"setName"`
		Primary bool   `bson:"isWritablePrimary"`
	}
	if client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello) != nil || hello.SetName == "" || !hello.Primary {
		return ErrServiceUnavailable
	}
	// A missing fixed non-user key is expected, but read permission is not.
	err := client.Database(serviceDatabase).Collection("pending_accounts").FindOne(ctx, bson.D{{Key: "_id", Value: "__identity_readiness__"}}, options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})).Err()
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return ErrServiceUnavailable
	}
	return nil
}

func verifyRuntimeRole(ctx context.Context, client *mongo.Client) error {
	var status struct {
		Auth struct {
			Users      []bson.M `bson:"authenticatedUsers"`
			Privileges []struct {
				Resource struct {
					DB         string `bson:"db"`
					Collection string `bson:"collection"`
					Any        bool   `bson:"anyResource"`
					Cluster    bool   `bson:"cluster"`
				} `bson:"resource"`
				Actions []string `bson:"actions"`
			} `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	if client.Database("admin").RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}).Decode(&status) != nil {
		return ErrServiceUnavailable
	}
	if len(status.Auth.Users) != 1 || len(status.Auth.Privileges) == 0 {
		return ErrUnsafeConfiguration
	}
	required := map[string]map[string]bool{
		"pending_accounts":   {"find": false, "insert": false, "update": false, "createIndex": false, "listIndexes": false},
		"sessions":           {"find": false, "insert": false, "update": false, "remove": false, "createIndex": false, "listIndexes": false},
		"staging_cka_tokens": {"find": false, "insert": false, "update": false, "createIndex": false, "listIndexes": false},
	}
	for _, p := range status.Auth.Privileges {
		if p.Resource.Any || p.Resource.Cluster || p.Resource.DB != serviceDatabase {
			return ErrUnsafeConfiguration
		}
		actions, known := required[p.Resource.Collection]
		if !known {
			return ErrUnsafeConfiguration
		}
		for _, a := range p.Actions {
			if _, allowed := actions[a]; !allowed {
				return ErrUnsafeConfiguration
			}
			actions[a] = true
		}
	}
	for _, actions := range required {
		for _, present := range actions {
			if !present {
				return ErrUnsafeConfiguration
			}
		}
	}
	return nil
}
