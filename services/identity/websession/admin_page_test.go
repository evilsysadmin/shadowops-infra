package websession

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestStagingAdminPageEnforcesHostMethodAndNoStore(t *testing.T) {
	for _, tc := range []struct {
		method, host, path string
		tls                bool
		want               int
	}{
		{"GET", stagingHost, "/admin", true, 200},
		{"GET", stagingHost, "/assets/admin.js", true, 200},
		{"POST", stagingHost, "/admin", true, 405},
		{"GET", "other.invalid", "/admin", true, 404},
		{"GET", stagingHost, "/admin", false, 404},
		{"GET", stagingHost, "/admin?user=alice", true, 404},
	} {
		r := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
		r.Host = tc.host
		if tc.tls {
			r.TLS = &tls.ConnectionState{}
		} else {
			r.TLS = nil
		}
		w := httptest.NewRecorder()
		StagingAdminPage(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s returned %d", tc.method, tc.path, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("admin page is cacheable")
		}
		if tc.want == 200 && w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
}
