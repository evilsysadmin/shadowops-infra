package websession

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func testCredentials() ConsumerCredentials {
	keys := make(ConsumerCredentials)
	for index, app := range []issuance.Application{issuance.ChessStudio, issuance.Chronicles, issuance.CKASimulator} {
		keys[app] = "soc1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 10)}, 32))
	}
	return keys
}

func evidenceRequest(t *testing.T, server *httptest.Server, credential string, c claims, mutate func(*http.Request), want int) []byte {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"subject": c.Subject, "session_version": c.Version, "token_jti": c.JTI})
	r, err := http.NewRequest("POST", server.URL+FreshnessPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = stagingHost
	r.Header.Set("Authorization", "Bearer "+credential)
	r.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(r)
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != want {
		t.Fatalf("freshness HTTP status=%d want=%d: %v", response.StatusCode, want, err)
	}
	if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("service response exposed a cookie, browser CORS or cached evidence")
	}
	return data
}

func TestTrustedFreshnessTransportBindsCallerToAudienceAndChecksLogout(t *testing.T) {
	f := setup(t)
	cookie := f.login(t, f.web)
	keys := testCredentials()
	s, err := NewStagingServiceHandler(t.Context(), f.issuer, testSeedForService(), keys)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s)
	defer server.Close()
	tokens := make(map[issuance.Application]claims)
	for origin, app := range consumers {
		tokens[app] = f.appClaims(t, f.web, origin)
	}
	for caller, key := range keys {
		for audience, token := range tokens {
			want := 401
			if caller == audience {
				want = 200
			}
			data := evidenceRequest(t, server, key, token, nil, want)
			if want != 200 {
				continue
			}
			var result issuance.ApplicationFreshnessEvidence
			if json.Unmarshal(data, &result) != nil || result.Audience != caller || result.Issuer != StagingOrigin || result.Subject != token.Subject || result.SessionVersion != token.Version || result.TokenJTI != token.JTI || !result.AccountActive || !result.SessionActive || !result.TokenActive || result.CheckedAt > time.Now().Unix() || time.Now().Unix()-result.CheckedAt > 2 {
				t.Fatal("freshness evidence was not current and bound to the exact claims/caller")
			}
		}
	}
	if err := f.issuer.Logout(t.Context(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	for app, token := range tokens {
		evidenceRequest(t, server, keys[app], token, nil, 401)
	}
}

func testSeedForService() []byte { return bytes.Repeat([]byte{0x66}, 32) }

func TestServiceExposesOnlyExplicitlyRegisteredConsumerOriginsAndReturnTargets(t *testing.T) {
	f := setup(t)
	cookie := f.login(t, f.web)
	key := testCredentials()[issuance.Chronicles]
	service, err := NewStagingServiceHandler(t.Context(), f.issuer, testSeedForService(), ConsumerCredentials{issuance.Chronicles: key})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service)
	defer server.Close()
	for _, tc := range []struct {
		app  string
		want int
	}{{"chronicles", 200}, {"chess-studio", 400}, {"cka-simulator", 400}} {
		r, _ := http.NewRequest("GET", server.URL+"/login?app="+tc.app, nil)
		r.Host = stagingHost
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.want {
			t.Fatal("unregistered login return target enabled", tc.app, response.StatusCode)
		}
	}
	for origin, app := range consumers {
		r, _ := http.NewRequest("POST", server.URL+"/api/identity/token", strings.NewReader("{}"))
		r.Host = stagingHost
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		response, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		want := 403
		if app == issuance.Chronicles {
			want = 200
		}
		if response.StatusCode != want {
			t.Fatal("unregistered consumer could mint a browser token", app, response.StatusCode)
		}
	}
}

func TestTrustedFreshnessDeniesUserProofsInjectionAndUnavailableStore(t *testing.T) {
	f := setup(t)
	cookie := f.login(t, f.web)
	keys := testCredentials()
	s, err := NewStagingServiceHandler(t.Context(), f.issuer, testSeedForService(), keys)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s)
	defer server.Close()
	token := f.appClaims(t, f.web, "https://staging.chronicles.shadowops.dpdns.org")
	key := keys[issuance.Chronicles]
	for _, bad := range []string{"", "synthetic-password", cookie.Value, "eyJhbGciOiJFZERTQSJ9.e30.signature"} {
		evidenceRequest(t, server, bad, token, nil, 401)
	}
	for _, tc := range []struct {
		mutate func(*http.Request)
		want   int
	}{
		{func(r *http.Request) { r.Header.Set("Origin", "https://staging.chronicles.shadowops.dpdns.org") }, 403},
		{func(r *http.Request) { r.AddCookie(cookie) }, 403},
		{func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+key) }, 401},
		{func(r *http.Request) { r.Host = "id.shadowops.dpdns.org" }, 403},
		{func(r *http.Request) { r.Method = "OPTIONS" }, 405},
		{func(r *http.Request) { r.URL.RawQuery = "audience=chess-studio" }, 400},
		{func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"audience":"chess-studio"}`))
			r.ContentLength = -1
		}, 400},
	} {
		evidenceRequest(t, server, key, token, tc.mutate, tc.want)
	}
	wrong := token
	wrong.Version++
	evidenceRequest(t, server, key, wrong, nil, 401)
	evidenceRequest(t, server, key, token, nil, 200)
	if err := f.client.Disconnect(t.Context()); err != nil {
		t.Fatal(err)
	}
	evidenceRequest(t, server, key, token, nil, 503)
}

func TestTrustedFreshnessConfigurationRequiresIndependentCanonicalKeys(t *testing.T) {
	f := setup(t)
	keys := testCredentials()
	for _, credentials := range []ConsumerCredentials{
		nil,
		{issuance.Chronicles: "plain-password"},
		{issuance.Chronicles: "soc1_" + strings.Repeat("A", 42) + "B"},
		{issuance.Chronicles: keys[issuance.Chronicles], issuance.ChessStudio: keys[issuance.Chronicles]},
		{issuance.Application("unknown-app"): keys[issuance.Chronicles]},
	} {
		if handler, err := NewStagingServiceHandler(t.Context(), f.issuer, testSeedForService(), credentials); err == nil || handler != nil {
			t.Fatal("unsafe service credentials accepted")
		}
	}
}
