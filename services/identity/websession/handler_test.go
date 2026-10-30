package websession

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConstructorRefusesMissingRealIssuer(t *testing.T) {
	if h, err := NewStagingHandler(nil, make([]byte, 32)); err == nil || h != nil {
		t.Fatal("accepted missing Mongo issuer")
	}
}

// These requests must be rejected before any backend operation. Actual valid
// requests are exercised only by the TLS+Mongo integration suite.
func TestTransportSecurityAndPreflightBeforeBackendAccess(t *testing.T) {
	h := &Handler{}
	for _, tc := range []struct {
		name, method, host, origin, contentType, body string
		tls                                           bool
		want                                          int
	}{
		{"plain HTTP", "POST", stagingHost, StagingOrigin, "application/json", "{}", false, 403},
		{"wrong host", "POST", "id.shadowops.dpdns.org", StagingOrigin, "application/json", "{}", true, 403},
		{"no origin", "POST", stagingHost, "", "application/json", "{}", true, 403},
		{"form CSRF", "POST", stagingHost, StagingOrigin, "application/x-www-form-urlencoded", "subject=x&password=y", true, 415},
		{"simple content type", "POST", stagingHost, StagingOrigin, "text/plain", "{}", true, 415},
		{"GET mutation", "GET", stagingHost, StagingOrigin, "application/json", "{}", true, 405},
		{"non-object", "POST", stagingHost, StagingOrigin, "application/json", "null", true, 400},
		{"trailing JSON", "POST", stagingHost, StagingOrigin, "application/json", "{} {}", true, 400},
		{"unprovisioned readiness", "GET", stagingHost, "", "", "", true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/api/identity/login"
			if tc.name == "unprovisioned readiness" {
				path = "/readyz"
			}
			r := httptest.NewRequest(tc.method, "https://"+tc.host+path, strings.NewReader(tc.body))
			r.Host = tc.host
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", stagingHost)
			r.TLS = nil
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || w.Header().Get("Set-Cookie") != "" {
				t.Fatalf("unsafe request returned %d want=%d or changed cookie", w.Code, tc.want)
			}
		})
	}
	for origin := range consumers {
		for _, headers := range []string{"content-type", "Content-Type", "content-type, authorization"} {
			r := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
			r.Header.Set("Origin", origin)
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 204
			if headers == "content-type, authorization" {
				want = 403
			}
			if w.Code != want || w.Header().Get("Access-Control-Allow-Origin") != origin || w.Header().Get("Access-Control-Allow-Origin") == "*" {
				t.Fatal("unexpected preflight result", w.Code)
			}
		}
	}
	for _, change := range []string{"cross-site", "duplicate-origin"} {
		r := httptest.NewRequest("POST", StagingOrigin+"/api/identity/login", strings.NewReader("{}"))
		r.Header.Set("Origin", StagingOrigin)
		if change == "cross-site" {
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		} else {
			r.Header.Add("Origin", StagingOrigin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("accepted ambiguous origin or cross-site metadata")
		}
	}
}

func TestLimiterConcurrentCapResetAndGlobalQuota(t *testing.T) {
	var l limiter
	now := time.Now()
	var accepted atomic.Int64
	var group sync.WaitGroup
	for range 50 {
		group.Go(func() {
			if l.allow("127.0.0.1", true, now) {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 10 {
		t.Fatal("concurrent password attempts exceeded peer quota", accepted.Load())
	}
	if !l.allow("127.0.0.1", true, now.Add(time.Minute)) {
		t.Fatal("quota did not reset")
	}
	var global limiter
	for i := range 60 {
		if !global.allow(string(rune(i+100)), true, now) {
			t.Fatal("unexpected global rejection")
		}
	}
	if global.allow("another-peer", true, now) {
		t.Fatal("global password quota exceeded")
	}
	if !global.allow("another-peer", false, now) {
		t.Fatal("password quota blocked existing session operations")
	}
}

func TestForgedForwardedAddressesCannotResetPasswordQuota(t *testing.T) {
	h := &Handler{}
	for i := range 11 {
		r := httptest.NewRequest("POST", StagingOrigin+"/api/identity/login", strings.NewReader("{}"))
		r.Header.Set("Origin", StagingOrigin)
		r.Header.Set("Content-Type", "text/plain")
		r.Header.Set("X-Forwarded-For", string(rune(i+100)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := http.StatusUnsupportedMediaType
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatal("forged proxy header bypassed peer quota", w.Code)
		}
	}
}
