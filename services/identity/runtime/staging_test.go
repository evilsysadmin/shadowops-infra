package runtime

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/core"
)

func testSeed() []byte { return bytes.Repeat([]byte{0x44}, 32) }
func TestStagingOnlyAndLoopbackOnly(t *testing.T) {
	for _, env := range []string{"", "prod", "production", "development", " STAGING ", "Staging"} {
		if _, err := NewStagingHandler(env, testSeed()); err == nil {
			t.Errorf("accepted %q", env)
		}
	}
	if _, err := NewStagingHandler("staging", nil); err == nil {
		t.Fatal("accepted missing secret")
	}
	h, err := NewStagingHandler("staging", testSeed())
	if err != nil || h == nil {
		t.Fatal(err)
	}
	server := StandaloneHTTPServer(h)
	if server.Addr != "127.0.0.1:9187" || server.ReadHeaderTimeout == 0 || server.MaxHeaderBytes > 8192 {
		t.Fatal("listener not hardened")
	}
}
func TestOnlyPublicJWKSAndLivenessNoAuth(t *testing.T) {
	h, err := NewStagingHandler("staging", testSeed())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/livez", 200}, {"GET", "/readyz", 503}, {"GET", "/api/identity/jwks", 200},
		{"POST", "/api/identity/jwks", 405}, {"POST", "/api/identity/token", 404},
		{"POST", "/api/identity/login", 404}, {"GET", "/api/identity/session", 404},
		{"GET", "/", 404}, {"GET", "/api/identity/authorize", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s returned %d want %d", tc.method, tc.path, w.Code, tc.want)
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Fatal("bootstrap must not set cookies")
		}
		if tc.path == "/readyz" && tc.method == "GET" && w.Code == 200 {
			t.Fatal("unsafe readiness")
		}
		if tc.path == "/api/identity/jwks" && tc.method == "GET" {
			var set core.KeySet
			if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
				t.Fatal("invalid JWKS")
			}
			if strings.Contains(w.Body.String(), `"d"`) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("private key or wrong caching")
			}
		}
	}
}
func TestProtectedStagingSecretFileFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed")
	if err := os.WriteFile(path, testSeed(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStagingSeed("staging", path); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"production", "development", ""} {
		if _, err := LoadStagingSeed(env, path); err == nil {
			t.Fatal("accepted unsafe env")
		}
	}
	if _, err := LoadStagingSeed("staging", "seed"); err == nil {
		t.Fatal("accepted relative seed path")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStagingSeed("staging", path); err == nil {
		t.Fatal("accepted world-readable seed")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStagingSeed("staging", link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := LoadStagingSeed("staging", dir); err == nil {
		t.Fatal("accepted directory")
	}
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStagingSeed("staging", path); err == nil {
		t.Fatal("accepted short seed")
	}
}
