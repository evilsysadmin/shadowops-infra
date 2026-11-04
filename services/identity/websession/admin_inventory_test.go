package websession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/admininventory"
	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func adminInventoryRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, StagingOrigin+AdminInventoryPath, strings.NewReader(`{"after":"","limit":20}`))
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", StagingOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "so1_" + strings.Repeat("a", 43)})
	return r
}

func TestAdminInventoryTransportRequiresSameOriginSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"wrong-host", func(r *http.Request) { r.Host = "other.invalid" }, 404},
		{"no-tls", func(r *http.Request) { r.TLS = nil }, 404},
		{"get", func(r *http.Request) { r.Method = "GET" }, 405},
		{"other-origin", func(r *http.Request) { r.Header.Set("Origin", "https://staging.chronicles.shadowops.dpdns.org") }, 403},
		{"missing-origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "subject=someone" }, 403},
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") }, 403},
		{"non-json", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
		{"missing-cookie", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"duplicate-cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: "so1_" + strings.Repeat("a", 43)})
		}, 401},
		{"forged-role", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"after":"","limit":20,"role":"admin"}`))
		}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := &adminInventoryHandler{read: func(context.Context, string, string, int) (admininventory.Page, error) {
				called = true
				return admininventory.Page{}, nil
			}}
			r := adminInventoryRequest()
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || called {
				t.Fatalf("status=%d called=%v", w.Code, called)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

func TestAdminInventoryTransportDelegatesAuthorizationAndDoesNotExposeErrors(t *testing.T) {
	calls := 0
	h := &adminInventoryHandler{read: func(_ context.Context, handle, after string, limit int) (admininventory.Page, error) {
		calls++
		if len(handle) != 47 || after != "" || limit != 20 {
			t.Fatal("incorrect request forwarded")
		}
		if calls == 1 {
			return admininventory.Page{}, issuance.ErrDenied
		}
		if calls == 2 {
			return admininventory.Page{}, errors.New("database secret")
		}
		return admininventory.Page{Accounts: []admininventory.Account{{Name: "alice"}}}, nil
	}}
	for _, expected := range []int{401, 503, 200} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, adminInventoryRequest())
		if w.Code != expected || strings.Contains(w.Body.String(), "database secret") {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
	if _, err := NewStagingAdminInventoryHandler(nil); err == nil {
		t.Fatal("nil issuer accepted")
	}
}
