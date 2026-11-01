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
	"strings"
	"testing"
	"time"
)

const testAliasSubject = "11111111-1111-4111-8111-111111111111"
const testAliasOther = "22222222-2222-4222-8222-222222222222"

func aliasTestSecret() string {
	return "soa1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
}

func aliasTestRequest(body, secret string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://"+serviceHost+AdminAliasesPath, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func aliasTestBody(body string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(body))
}

func TestAdminAliasRPCIsOptInAndUsesIndependentSecret(t *testing.T) {
	cfg := syntheticServiceConfig(t)
	if _, _, _, err := cfg.validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	cfg.AdminAliasCredential = aliasTestSecret()
	if _, _, _, err := cfg.validate(time.Now()); err != nil {
		t.Fatalf("correct scoped staging credential rejected: %v", err)
	}
	for _, invalid := range []string{
		"soc1_" + strings.Repeat("x", 43), "user-password",
		"soa1_" + strings.Repeat("x", 43), "soa1_",
	} {
		cfg.AdminAliasCredential = invalid
		if _, _, _, err := cfg.validate(time.Now()); err == nil {
			t.Fatalf("invalid alias credential accepted: %q", invalid)
		}
	}
	if _, err := newAdminAliasHandler("", func(context.Context, []string) (map[string]string, error) {
		return nil, nil
	}); err == nil {
		t.Fatal("missing privileged credential enabled endpoint")
	}
	if _, err := newAdminAliasHandler(aliasTestSecret(), nil); err == nil {
		t.Fatal("missing storage resolver enabled endpoint")
	}
}

func TestAdminAliasRPCRejectsBrowserAndUnauthorizedCallsBeforeReading(t *testing.T) {
	calls := 0
	h, err := newAdminAliasHandler(aliasTestSecret(), func(context.Context, []string) (map[string]string, error) {
		calls++
		return map[string]string{testAliasSubject: "alice"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"subjects":["` + testAliasSubject + `"]}`
	scenarios := []struct {
		name   string
		change func(*http.Request)
		want   int
	}{
		{"missing credential", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"browser credential", func(r *http.Request) { r.Header.Set("Authorization", "Bearer user-jwt") }, 401},
		{"freshness credential", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer soc1_"+strings.Repeat("x", 43))
		}, 401},
		{"duplicate bearer", func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer "+aliasTestSecret())
		}, 401},
		{"origin", func(r *http.Request) {
			r.Header.Set("Origin", "https://staging.chronicles.shadowops.dpdns.org")
		}, 403},
		{"cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "session", Value: "x"})
		}, 403},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"http", func(r *http.Request) { r.TLS = nil }, 403},
		{"wrong host", func(r *http.Request) { r.Host = "id.shadowops.dpdns.org" }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "admin=true" }, 400},
		{"method", func(r *http.Request) { r.Method = "GET" }, 405},
		{"wrong content", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"unknown field", func(r *http.Request) {
			r.Body = aliasTestBody(`{"subjects":["` + testAliasSubject + `"],"role":"admin"}`)
		}, 400},
		{"duplicate subjects", func(r *http.Request) {
			r.Body = aliasTestBody(`{"subjects":["` + testAliasSubject + `","` + testAliasSubject + `"]}`)
		}, 400},
		{"bad subject", func(r *http.Request) {
			r.Body = aliasTestBody(`{"subjects":["../../secret"]}`)
		}, 400},
		{"empty subjects", func(r *http.Request) {
			r.Body = aliasTestBody(`{"subjects":[]}`)
		}, 400},
		{"too many", func(r *http.Request) {
			subjects := make([]string, 41)
			for i := range subjects {
				subjects[i] = testAliasSubject
			}
			data, _ := json.Marshal(map[string]any{"subjects": subjects})
			r.Body = aliasTestBody(string(data))
		}, 400},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			request := aliasTestRequest(body, aliasTestSecret())
			tc.change(request)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status %d want %d", response.Code, tc.want)
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" ||
				response.Header().Get("Set-Cookie") != "" ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("browser CORS, cookie, or caching leak")
			}
		})
	}
	if calls != 0 {
		t.Fatalf("queried storage %d times for invalid requests", calls)
	}
}

func TestAdminAliasRPCReturnsOnlyRequestedAliasesAndRateLimits(t *testing.T) {
	calls := 0
	h, err := newAdminAliasHandler(aliasTestSecret(), func(_ context.Context, subjects []string) (map[string]string, error) {
		calls++
		if len(subjects) != 2 || subjects[0] != testAliasSubject || subjects[1] != testAliasOther {
			t.Fatal("unexpected requested subjects")
		}
		return map[string]string{
			testAliasSubject:                       "alice",
			testAliasOther:                         "invalid name with spaces",
			"33333333-3333-4333-8333-333333333333": "unrequested",
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"subjects":["` + testAliasSubject + `","` + testAliasOther + `"]}`
	for i := 0; i < 30; i++ {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, aliasTestRequest(body, aliasTestSecret()))
		if response.Code != 200 {
			t.Fatalf("request %d denied: %d", i, response.Code)
		}
		var result struct {
			Aliases map[string]string `json:"aliases"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil ||
			len(result.Aliases) != 1 || result.Aliases[testAliasSubject] != "alice" {
			t.Fatalf("unexpected minimized aliases: %s %v", response.Body.String(), err)
		}
		if response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("sensitive response leaked to browser cache or CORS")
		}
	}
	rate := httptest.NewRecorder()
	h.ServeHTTP(rate, aliasTestRequest(body, aliasTestSecret()))
	if rate.Code != 429 || calls != 30 || rate.Header().Get("Retry-After") != "60" {
		t.Fatalf("rate guard failed: status=%d reads=%d", rate.Code, calls)
	}
	unavailable, err := newAdminAliasHandler(aliasTestSecret(), func(context.Context, []string) (map[string]string, error) {
		return nil, errors.New("mongo error containing private details")
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	unavailable.ServeHTTP(response, aliasTestRequest(body, aliasTestSecret()))
	if response.Code != 503 || strings.Contains(response.Body.String(), "mongo error") {
		t.Fatal("store failure leaked internals")
	}
}
