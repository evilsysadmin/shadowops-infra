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

type chroniclesRoundTrip func(*http.Request) (*http.Response, error)

func (f chroniclesRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func chroniclesRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, StagingOrigin+AdminChroniclesPath, strings.NewReader(`{"after":""}`))
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Origin", StagingOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "so1_" + strings.Repeat("a", 43)})
	return r
}

func TestChroniclesActivityRequiresAdminAndKeepsTokenServerSide(t *testing.T) {
	issued := 0
	calls := 0
	h := &chroniclesAdminHandler{read: func(context.Context, string, string, int) (admininventory.Page, error) {
		return admininventory.Page{}, issuance.ErrDenied
	}, sign: func(context.Context, string) (string, error) { issued++; return "private-token", nil }, client: &http.Client{Transport: chroniclesRoundTrip(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected") })}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, chroniclesRequest())
	if w.Code != 401 || issued != 0 || calls != 0 {
		t.Fatalf("denied: %d %d %d", w.Code, issued, calls)
	}
	h.read = func(context.Context, string, string, int) (admininventory.Page, error) {
		return admininventory.Page{}, nil
	}
	h.client.Transport = chroniclesRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != chroniclesRosterURL || r.Header.Get("Authorization") != "Bearer private-token" {
			t.Fatal("incorrect downstream request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"users":[{"username":"shadowops:staging:11111111-1111-4111-8111-111111111111","mapId":"town","savedExpeditions":2},{"username":"legacy","mapId":"private"}]}`)), Header: make(http.Header)}, nil
	})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, chroniclesRequest())
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "11111111-1111-4111-8111-111111111111") || !strings.Contains(body, "town") || strings.Contains(body, "private") || strings.Contains(body, "private-token") || calls != 1 {
		t.Fatalf("unexpected response %d %s", w.Code, body)
	}
}

func TestChroniclesActivityRejectsWrongOriginAndDownstreamErrors(t *testing.T) {
	calls := 0
	h := &chroniclesAdminHandler{read: func(context.Context, string, string, int) (admininventory.Page, error) {
		calls++
		return admininventory.Page{}, nil
	}, sign: func(context.Context, string) (string, error) { return "token", nil }, client: &http.Client{Transport: chroniclesRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("private error") })}}
	r := chroniclesRequest()
	r.Header.Set("Origin", "https://evil.invalid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || calls != 0 {
		t.Fatalf("wrong origin %d %d", w.Code, calls)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, chroniclesRequest())
	if w.Code != 503 || strings.Contains(w.Body.String(), "private error") {
		t.Fatalf("downstream failure %d %s", w.Code, w.Body.String())
	}
}

func TestChroniclesPermissionDenialIsDistinctFromServiceFailure(t *testing.T) {
	for _, tc := range []struct{ upstream, want int }{{403, 403}, {401, 503}, {500, 503}} {
		t.Run(http.StatusText(tc.upstream), func(t *testing.T) {
			h := &chroniclesAdminHandler{read: func(context.Context, string, string, int) (admininventory.Page, error) {
				return admininventory.Page{}, nil
			}, sign: func(context.Context, string) (string, error) { return "token", nil }, client: &http.Client{Transport: chroniclesRoundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.upstream, Body: io.NopCloser(strings.NewReader("private detail")), Header: make(http.Header)}, nil
			})}}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, chroniclesRequest())
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private detail") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestChroniclesActivityRejectsForgedInputsBeforeSigning(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"no TLS", func(r *http.Request) { r.TLS = nil }, 404},
		{"wrong host", func(r *http.Request) { r.Host = "other.invalid" }, 404},
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }, 405},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"authorization header", func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "subject=forged" }, 403},
		{"unknown field", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"after":"","role":"admin"}`)) }, 400},
		{"no cookie", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := &chroniclesAdminHandler{read: func(context.Context, string, string, int) (admininventory.Page, error) {
				calls++
				return admininventory.Page{}, nil
			}, sign: func(context.Context, string) (string, error) { calls++; return "token", nil }, client: &http.Client{}}
			r := chroniclesRequest()
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want || calls != 0 {
				t.Fatalf("status=%d calls=%d", w.Code, calls)
			}
		})
	}
}
