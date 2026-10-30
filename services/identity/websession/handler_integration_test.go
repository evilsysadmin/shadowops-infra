package websession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/core"
	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"github.com/evilsysadmin/shadowops-infra/services/identity/password"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const testSubject = "11111111-1111-4111-8111-111111111111"
const testPassword = "correct-synthetic-password-2026"
const replicaURL = "mongodb://127.0.0.1:27018/?replicaSet=identity-rs&directConnection=true"

type fixture struct {
	issuer *issuance.Issuer
	db     *mongo.Database
	client *mongo.Client
	h      *Handler
	server *httptest.Server
	web    *http.Client
}

func setup(t *testing.T) *fixture {
	t.Helper()
	uri := os.Getenv("IDENTITY_MONGO_REPLICA_TEST_URL")
	if uri == "" {
		t.Skip("ephemeral local Mongo replica set not configured")
	}
	if uri != replicaURL {
		t.Fatal("refusing non-local Mongo fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Fatal(err)
	}
	db := client.Database("shadowops_identity_staging")
	collections := []string{"pending_accounts", "sessions", "staging_cka_tokens"}
	for _, name := range collections {
		if err := db.Collection(name).Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		for _, name := range collections {
			_ = db.Collection(name).Drop(cleanup)
		}
		_ = client.Disconnect(cleanup)
	})
	hash, err := password.HashNew(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Collection("pending_accounts").InsertOne(ctx, bson.D{
		{Key: "_id", Value: testSubject}, {Key: "environment", Value: "staging"},
		{Key: "state", Value: "active"}, {Key: "credentials_disabled", Value: false},
		{Key: "credential_hash", Value: hash}, {Key: "credential_version", Value: int64(1)},
		{Key: "session_version", Value: int64(1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := issuance.NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewStagingHandler(issuer, bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	web := *server.Client() // Server.Client returns the same pointer on each call.
	web.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{issuer: issuer, db: db, client: client, h: h, server: server, web: &web}
}

func (f *fixture) browser() *http.Client {
	web := *f.server.Client()
	return &web
}

func (f *fixture) request(t *testing.T, web *http.Client, path, origin, body string, want int) (http.Header, []byte) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = stagingHost
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	response, err := web.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s returned %d, want %d: %s", path, response.StatusCode, want, data)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("session response can be cached or sniffed")
	}
	return response.Header, data
}

func (f *fixture) login(t *testing.T, web *http.Client) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"subject": testSubject, "password": testPassword})
	headers, data := f.request(t, web, "/api/identity/login", StagingOrigin, string(body), 204)
	response := &http.Response{Header: headers}
	cookies := response.Cookies()
	if len(cookies) != 1 || len(data) != 0 {
		t.Fatal("login did not return exactly one cookie and an empty body")
	}
	c := cookies[0]
	if c.Name != CookieName || c.Domain != "" || c.Path != "/" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Expires.IsZero() || c.MaxAge != 0 || len(c.Value) != 47 {
		t.Fatal("unsafe session cookie")
	}
	return c
}

type claims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Aud     string `json:"aud"`
	JTI     string `json:"jti"`
	Version int64  `json:"sv"`
	Issued  int64  `json:"iat"`
	NBF     int64  `json:"nbf"`
	Expires int64  `json:"exp"`
}

func (f *fixture) appClaims(t *testing.T, web *http.Client, origin string) claims {
	t.Helper()
	headers, body := f.request(t, web, "/api/identity/token", origin, "{}", 200)
	if headers.Get("Access-Control-Allow-Origin") != origin || headers.Get("Access-Control-Allow-Credentials") != "true" || headers.Get("Set-Cookie") != "" {
		t.Fatal("token exchange changed cookie or CORS origin")
	}
	var response struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(body, &response) != nil {
		t.Fatal("invalid token response")
	}
	parts := strings.Split(response.Token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT")
	}
	var keys core.KeySet
	if json.Unmarshal(f.h.public, &keys) != nil || len(keys.Keys) != 1 {
		t.Fatal("invalid public JWKS")
	}
	key, err := base64.RawURLEncoding.DecodeString(keys.Keys[0].X)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatal("invalid public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("invalid actual JWT signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c claims
	if err != nil || json.Unmarshal(payload, &c) != nil || c.Issuer != StagingOrigin || c.Subject != testSubject || c.Aud != string(consumers[origin]) || c.Version != 1 || c.JTI == "" || c.Expires <= time.Now().Unix() || c.Expires-c.Issued > 120 || c.NBF > time.Now().Unix() {
		t.Fatal("token did not retain central identity and origin-bound audience")
	}
	return c
}

func (f *fixture) fresh(t *testing.T, c claims, want bool) {
	t.Helper()
	checker, err := issuance.NewStagingAppFreshness(f.issuer, issuance.Application(c.Aud))
	if err != nil {
		t.Fatal(err)
	}
	_, err = checker.Check(context.Background(), c.Subject, c.Version, c.JTI)
	if (err == nil) != want {
		t.Fatalf("%s freshness accepted=%v, want %v", c.Aud, err == nil, want)
	}
}

func TestHTTPSLoginOnceThreeAppsRefreshAndCentralLogout(t *testing.T) {
	f := setup(t)
	cookie := f.login(t, f.web)
	// Keep an independent browser with the stale original handle to test replay.
	stale := f.browser()
	stale.Transport = &cookieTransport{base: stale.Transport, cookie: cookie}
	var old []claims
	for origin := range consumers {
		c := f.appClaims(t, f.web, origin)
		f.fresh(t, c, true)
		old = append(old, c)
	}
	for collection, want := range map[string]int64{"pending_accounts": 1, "sessions": 1, "staging_cka_tokens": 3} {
		got, err := f.db.Collection(collection).CountDocuments(context.Background(), bson.D{})
		if err != nil || got != want {
			t.Fatalf("%s count=%d want=%d: %v", collection, got, want, err)
		}
	}
	var before struct {
		Expires time.Time `bson:"expires_at"`
	}
	if err := f.db.Collection("sessions").FindOne(context.Background(), bson.D{}).Decode(&before); err != nil {
		t.Fatal(err)
	}
	f.request(t, f.web, "/api/identity/refresh", "https://staging.chronicles.shadowops.dpdns.org", "{}", 204)
	f.request(t, stale, "/api/identity/token", "https://staging.chronicles.shadowops.dpdns.org", "{}", 401)
	headers, _ := f.request(t, stale, "/api/identity/refresh", StagingOrigin, "{}", 401)
	if headers.Get("Set-Cookie") != "" {
		t.Fatal("replayed refresh can overwrite the rotated cookie")
	}
	var after struct {
		Expires time.Time `bson:"expires_at"`
	}
	if err := f.db.Collection("sessions").FindOne(context.Background(), bson.D{}).Decode(&after); err != nil || !before.Expires.Equal(after.Expires) {
		t.Fatal("HTTP refresh extended absolute session expiry", err)
	}
	for _, c := range old {
		f.fresh(t, c, false)
	}
	var current []claims
	for origin := range consumers {
		c := f.appClaims(t, f.web, origin)
		f.fresh(t, c, true)
		current = append(current, c)
	}
	other := f.browser()
	other.Jar, _ = cookiejar.New(nil)
	f.login(t, other)
	otherClaims := f.appClaims(t, other, "https://staging.cka.shadowops.dpdns.org")
	headers, _ = f.request(t, f.web, "/api/identity/logout", "https://staging.chess-studio.shadowops.dpdns.org", "{}", 204)
	cleared := (&http.Response{Header: headers}).Cookies()
	if len(cleared) != 1 || cleared[0].Value != "" || cleared[0].MaxAge != -1 || !cleared[0].Secure || !cleared[0].HttpOnly || cleared[0].Path != "/" || cleared[0].Domain != "" {
		t.Fatal("logout did not securely clear the host cookie")
	}
	for _, c := range current {
		f.fresh(t, c, false)
	}
	for origin := range consumers {
		f.request(t, f.web, "/api/identity/token", origin, "{}", 401)
	}
	f.fresh(t, otherClaims, true)
}

type cookieTransport struct {
	base   http.RoundTripper
	cookie *http.Cookie
}

func (t *cookieTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.AddCookie(t.cookie)
	return t.base.RoundTrip(r)
}

func TestHTTPSNegativeRequestsCannotChangeSessionOrAudience(t *testing.T) {
	f := setup(t)
	cookie := f.login(t, f.web)
	origin := "https://staging.chess-studio.shadowops.dpdns.org"
	f.request(t, f.web, "/api/identity/token", origin, `{"audience":"cka-simulator"}`, 400)
	f.request(t, f.web, "/api/identity/token", origin, `{"subject":"22222222-2222-4222-8222-222222222222"}`, 400)
	f.request(t, f.web, "/api/identity/token", origin, "{} {}", 400)
	f.request(t, f.web, "/api/identity/token", origin, strings.Repeat("x", 8193), 400)
	f.request(t, f.web, "/api/identity/login", origin, `{"subject":"`+testSubject+`","password":"`+testPassword+`"}`, 403)
	for _, badOrigin := range []string{"", "null", "https://evil.example", "https://staging.chess-studio.shadowops.dpdns.org.evil.example", "http://staging.chess-studio.shadowops.dpdns.org", "https://chess-studio.shadowops.dpdns.org"} {
		for _, path := range []string{"token", "logout", "refresh", "login"} {
			headers, _ := f.request(t, f.web, "/api/identity/"+path, badOrigin, "{}", 403)
			if headers.Get("Access-Control-Allow-Origin") != "" || headers.Get("Set-Cookie") != "" {
				t.Fatal("untrusted origin obtained CORS or cookie changes")
			}
		}
	}
	for _, body := range []string{`{"subject":"` + testSubject + `","password":"wrong"}`, `{"subject":"22222222-2222-4222-8222-222222222222","password":"` + testPassword + `"}`, `{"subject":"Matthias","password":"` + testPassword + `"}`} {
		headers, _ := f.request(t, f.web, "/api/identity/login", StagingOrigin, body, 401)
		if headers.Get("Set-Cookie") != "" {
			t.Fatal("denied login changed browser cookie")
		}
	}
	duplicate := f.browser()
	duplicate.Transport = &cookieTransport{base: &cookieTransport{base: duplicate.Transport, cookie: cookie}, cookie: cookie}
	f.request(t, duplicate, "/api/identity/logout", origin, "{}", 401)
	f.fresh(t, f.appClaims(t, f.web, origin), true)
	count, err := f.db.Collection("sessions").CountDocuments(context.Background(), bson.D{})
	if err != nil || count != 1 {
		t.Fatal("negative requests modified the source session", err)
	}
}

func TestHTTPSUnavailableStoreDoesNotClearOrCreateCookie(t *testing.T) {
	f := setup(t)
	f.login(t, f.web)
	if err := f.client.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"token", "refresh", "logout"} {
		headers, _ := f.request(t, f.web, "/api/identity/"+action, "https://staging.cka.shadowops.dpdns.org", "{}", 503)
		if headers.Get("Set-Cookie") != "" {
			t.Fatal("store failure created or cleared a session cookie")
		}
	}
	body := `{"subject":"` + testSubject + `","password":"` + testPassword + `"}`
	headers, _ := f.request(t, f.web, "/api/identity/login", StagingOrigin, body, 503)
	if headers.Get("Set-Cookie") != "" {
		t.Fatal("failed login returned a session cookie")
	}
}
