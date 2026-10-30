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
