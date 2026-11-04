package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func runtimeFixture(t *testing.T) ServiceConfig {
	t.Helper()
	uri := os.Getenv("IDENTITY_RUNTIME_MONGO_URL")
	if uri == "" {
		t.Skip("explicit TLS/authenticated localhost runtime replica not configured")
	}
	checkLocalRuntimeURI(t, uri)
	ca, err := os.ReadFile(os.Getenv("IDENTITY_RUNTIME_MONGO_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := syntheticServiceConfig(t)
	cfg.MongoURI = uri
	cfg.MongoCA = string(ca)
	return cfg
}

func checkLocalRuntimeURI(t *testing.T, uri string) {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "mongodb" || u.Host != "127.0.0.1:27019" || u.Path != "/"+serviceDatabase || u.Query().Get("replicaSet") != "identity-runtime-rs" || u.Query().Get("directConnection") != "true" || u.Query().Get("tls") != "true" || u.User == nil {
		t.Fatal("refusing non-local runtime fixture URI")
	}
}

func TestServiceRuntimeStartsOnlyWithNarrowTLSRoleAndServesRealAccountFlow(t *testing.T) {
	cfg := runtimeFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	service, err := NewStagingService(ctx, cfg)
	if err != nil {
		t.Fatal("TLS/authenticated runtime did not start", err)
	}
	t.Cleanup(func() { _ = service.Client.Disconnect(context.Background()) })
	server := httptest.NewUnstartedServer(service.Server.Handler)
	server.TLS = service.Server.TLSConfig
	server.StartTLS()
	defer server.Close()
	request := func(path, origin, body, credential string, cookie *http.Cookie, want int) (http.Header, []byte) {
		t.Helper()
		method := "POST"
		if path == "/livez" || path == "/readyz" || path == "/api/identity/release" {
			method = "GET"
		}
		r, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = serviceHost
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("runtime %s status=%d want=%d: %v", path, response.StatusCode, want, err)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("runtime response may be cached")
		}
		return response.Header, data
	}
	request("/livez", "", "", "", nil, 200)
	request("/readyz", "", "", "", nil, 200)
	request("/api/identity/admin/accounts", "https://"+serviceHost, `{"after":"","limit":20}`, "", nil, 404)
	_, release := request("/api/identity/release", "", "", "", nil, 200)
	var receipt map[string]string
	if json.Unmarshal(release, &receipt) != nil || len(receipt) != 3 || receipt["service"] != "shadowops-identity" || receipt["environment"] != "staging" || receipt["source_sha"] != BuildSHA {
		t.Fatal("incorrect runtime source receipt")
	}
	credentials := `{"username":"runtime_player","password":"synthetic-runtime-password-2026"}`
	_, registration := request("/api/identity/register", "https://"+serviceHost, credentials, "", nil, 201)
	if !bytes.Contains(registration, []byte(`"recoveryCode":"sor1_`)) {
		t.Fatal("runtime enrollment failed")
	}
	headers, _ := request("/api/identity/login", "https://"+serviceHost, credentials, "", nil, 204)
	cookies := (&http.Response{Header: headers}).Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("runtime did not issue protected cookie")
	}
	_, data := request("/api/identity/token", "https://staging.chronicles.shadowops.dpdns.org", "{}", "", cookies[0], 200)
	var token struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &token) != nil {
		t.Fatal("invalid runtime token")
	}
	parts := strings.Split(token.Token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT shape")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Subject string `json:"sub"`
		Version int64  `json:"sv"`
		JTI     string `json:"jti"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		t.Fatal("invalid runtime claims")
	}
	body, _ := json.Marshal(map[string]any{"subject": claims.Subject, "session_version": claims.Version, "token_jti": claims.JTI})
	request("/api/identity/freshness", "", string(body), cfg.Consumers[issuance.Chronicles], nil, 200)
	request("/api/identity/logout", "https://staging.chronicles.shadowops.dpdns.org", "{}", "", cookies[0], 204)
	request("/api/identity/freshness", "", string(body), cfg.Consumers[issuance.Chronicles], nil, 401)
}

func TestServiceRuntimeRejectsAdminBroadIncompleteAndUntrustedTLSClients(t *testing.T) {
	base := runtimeFixture(t)
	for _, key := range []string{"IDENTITY_RUNTIME_ADMIN_URI", "IDENTITY_RUNTIME_BROAD_URI", "IDENTITY_RUNTIME_INCOMPLETE_URI"} {
		t.Run(key, func(t *testing.T) {
			cfg := base
			cfg.MongoURI = os.Getenv(key)
			checkLocalRuntimeURI(t, cfg.MongoURI)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			service, err := NewStagingService(ctx, cfg)
			if service != nil || !errors.Is(err, ErrUnsafeConfiguration) {
				if service != nil {
					_ = service.Client.Disconnect(ctx)
				}
				t.Fatal("privileged/incomplete Mongo client was accepted", err)
			}
		})
	}
	wrongCA := syntheticServiceConfig(t)
	bad := base
	bad.MongoCA = wrongCA.MongoCA
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if service, err := NewStagingService(ctx, bad); err == nil || service != nil {
		if service != nil {
			_ = service.Client.Disconnect(ctx)
		}
		t.Fatal("untrusted Mongo TLS certificate accepted")
	}
}

func TestServiceRuntimeAdminInventoryOptInAndRoles(t *testing.T) {
	cfg := runtimeFixture(t)
	cfg.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_INVENTORY_URI")
	checkLocalRuntimeURI(t, cfg.AdminInventoryMongoURI)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, uri := range []string{cfg.MongoURI, os.Getenv("IDENTITY_RUNTIME_BROAD_URI"), os.Getenv("IDENTITY_RUNTIME_INCOMPLETE_URI"), os.Getenv("IDENTITY_RUNTIME_ADMIN_URI")} {
		bad := cfg
		bad.AdminInventoryMongoURI = uri
		service, err := NewStagingService(ctx, bad)
		if service != nil {
			if service.AdminClient != nil {
				_ = service.AdminClient.Disconnect(ctx)
			}
			_ = service.Client.Disconnect(ctx)
			t.Fatal("unsafe admin Mongo role accepted")
		}
		if err == nil {
			t.Fatal("unsafe admin Mongo role accepted")
		}
	}
	wrongRecent := cfg
	wrongRecent.AdminInventoryRecentAccess = true
	if service, err := NewStagingService(ctx, wrongRecent); err == nil || service != nil {
		if service != nil {
			_ = service.Client.Disconnect(ctx)
			if service.AdminClient != nil {
				_ = service.AdminClient.Disconnect(ctx)
			}
		}
		t.Fatal("missing token-read privilege accepted")
	}
	tooBroad := cfg
	tooBroad.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_INVENTORY_RECENT_URI")
	if service, err := NewStagingService(ctx, tooBroad); err == nil || service != nil {
		if service != nil {
			_ = service.Client.Disconnect(ctx)
			if service.AdminClient != nil {
				_ = service.AdminClient.Disconnect(ctx)
			}
		}
		t.Fatal("unrequested token-read privilege accepted")
	}
	service, err := NewStagingService(ctx, cfg)
	if err != nil {
		t.Fatal("inventory service did not start", err)
	}
	t.Cleanup(func() {
		_ = service.AdminClient.Disconnect(context.Background())
		_ = service.Client.Disconnect(context.Background())
	})
	narrow := service.AdminClient.Database(serviceDatabase)
	if err := narrow.Collection("admin_inventory_audit").FindOne(ctx, bson.M{}).Err(); err == nil || errors.Is(err, mongo.ErrNoDocuments) {
		t.Fatal("inventory principal can read audit history")
	}
	if _, err := narrow.Collection("pending_accounts").InsertOne(ctx, bson.M{"_id": "forbidden-inventory-insert"}); err == nil {
		t.Fatal("inventory principal can create accounts")
	}
	if _, err := narrow.Collection("sessions").DeleteOne(ctx, bson.M{"digest": "forbidden"}); err == nil {
		t.Fatal("inventory principal can delete sessions")
	}
	server := httptest.NewUnstartedServer(service.Server.Handler)
	server.TLS = service.Server.TLSConfig
	server.StartTLS()
	defer server.Close()
	getPage := func(want int) {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, server.URL+"/admin", nil)
		r.Host = serviceHost
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("admin page status %d, want %d", response.StatusCode, want)
		}
	}
	getPage(200)
	request := func(path, body string, cookie *http.Cookie, want int) (http.Header, []byte) {
		t.Helper()
		r, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = serviceHost
		r.Header.Set("Origin", "https://"+serviceHost)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s status=%d want=%d err=%v body=%s", path, response.StatusCode, want, err, data)
		}
		return response.Header, data
	}
	credentials := `{"username":"inventory_admin","password":"synthetic-inventory-password-2026"}`
	request("/api/identity/register", credentials, nil, 201)
	headers, _ := request("/api/identity/login", credentials, nil, 204)
	cookies := (&http.Response{Header: headers}).Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing login cookie")
	}
	request("/api/identity/admin/accounts", `{"after":"","limit":20}`, cookies[0], 401)
	_, _, tlsConfig, err := cfg.validate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root, err := mongo.Connect(options.Client().ApplyURI(os.Getenv("IDENTITY_RUNTIME_ADMIN_URI")).SetTLSConfig(tlsConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Disconnect(context.Background())
	accounts := root.Database(serviceDatabase).Collection("pending_accounts")
	if _, err := accounts.UpdateOne(ctx, bson.M{"alias_key": "inventory_admin", "source": "shadowops-identity"}, bson.M{"$set": bson.M{"role": "admin"}}); err != nil {
		t.Fatal(err)
	}
	_, data := request("/api/identity/admin/accounts", `{"after":"","limit":20}`, cookies[0], 200)
	var page struct {
		Accounts []struct {
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if json.Unmarshal(data, &page) != nil || len(page.Accounts) == 0 {
		t.Fatal("missing inventory")
	}
	found := false
	for _, a := range page.Accounts {
		if a.Name == "inventory_admin" {
			found = true
		}
	}
	if !found {
		t.Fatal("admin account absent")
	}
	var admin struct {
		Subject string `bson:"_id"`
	}
	if err := accounts.FindOne(ctx, bson.M{"alias_key": "inventory_admin", "source": "shadowops-identity"}).Decode(&admin); err != nil {
		t.Fatal(err)
	}
	count, err := root.Database(serviceDatabase).Collection("admin_inventory_audit").CountDocuments(ctx, bson.M{"action": "list_accounts", "actor": admin.Subject})
	if err != nil || count != 1 {
		t.Fatal("audit missing", count, err)
	}
	// A real audience-bound token exchange is observable briefly; it does not
	// claim that a game was played or retain a history beyond the token TTL.
	tokenRequest, err := http.NewRequest(http.MethodPost, server.URL+"/api/identity/token", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	tokenRequest.Host = serviceHost
	tokenRequest.Header.Set("Origin", "https://staging.chronicles.shadowops.dpdns.org")
	tokenRequest.Header.Set("Content-Type", "application/json")
	tokenRequest.AddCookie(cookies[0])
	tokenResponse, err := server.Client().Do(tokenRequest)
	if err != nil {
		t.Fatal(err)
	}
	tokenResponse.Body.Close()
	if tokenResponse.StatusCode != 200 {
		t.Fatal("token exchange failed", tokenResponse.StatusCode)
	}
	recentCfg := cfg
	recentCfg.AdminInventoryRecentAccess = true
	recentCfg.AdminInventoryMongoURI = os.Getenv("IDENTITY_RUNTIME_INVENTORY_RECENT_URI")
	recentService, err := NewStagingService(ctx, recentCfg)
	if err != nil {
		t.Fatal("recent-access service failed", err)
	}
	if err := recentService.AdminClient.Database(serviceDatabase).Collection("staging_cka_tokens").FindOne(ctx, bson.M{}).Err(); err == nil || errors.Is(err, mongo.ErrNoDocuments) {
		t.Fatal("inventory principal can read full token records")
	}
	defer recentService.Client.Disconnect(context.Background())
	defer recentService.AdminClient.Disconnect(context.Background())
	recentServer := httptest.NewUnstartedServer(recentService.Server.Handler)
	recentServer.TLS = recentService.Server.TLSConfig
	recentServer.StartTLS()
	defer recentServer.Close()
	server = recentServer
	_, data = request("/api/identity/admin/accounts", `{"after":"","limit":20}`, cookies[0], 200)
	var recent struct {
		Available bool `json:"recentAccessAvailable"`
		Accounts  []struct {
			Name string `json:"name"`
			Apps []struct {
				Application string `json:"application"`
			} `json:"recentApplications"`
		} `json:"accounts"`
	}
	if json.Unmarshal(data, &recent) != nil || !recent.Available {
		t.Fatal("recent access missing")
	}
	found = false
	for _, account := range recent.Accounts {
		if account.Name == "inventory_admin" && len(account.Apps) == 1 && account.Apps[0].Application == "chronicles" {
			found = true
		}
	}
	if !found {
		t.Fatal("actual token exchange absent", string(data))
	}
	request("/api/identity/logout", "{}", cookies[0], 204)
	request("/api/identity/admin/accounts", `{"after":"","limit":20}`, cookies[0], 401)
}
