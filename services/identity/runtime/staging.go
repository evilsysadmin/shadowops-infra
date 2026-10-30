// Package runtime hosts a configured staging TLS service and the older
// localhost-only health/JWKS bootstrap. Both refuse production configuration.
package runtime

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/core"
)

const LocalAddress = "127.0.0.1:9187"

var ErrUnsafeConfiguration = errors.New("unsafe staging Identity configuration")

func LoadStagingSeed(environment, filename string) ([]byte, error) {
	if environment != "staging" || !filepath.IsAbs(filename) {
		return nil, ErrUnsafeConfiguration
	}
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, ErrUnsafeConfiguration
	}
	data, err := os.ReadFile(filename)
	if err != nil || len(data) != 32 {
		return nil, ErrUnsafeConfiguration
	}
	return data, nil
}

func NewStagingHandler(environment string, seed []byte) (http.Handler, error) {
	if environment != "staging" {
		return nil, ErrUnsafeConfiguration
	}
	issuer, err := core.New(environment, seed)
	if err != nil {
		return nil, ErrUnsafeConfiguration
	}
	jwks, err := issuer.JWKS()
	if err != nil {
		return nil, ErrUnsafeConfiguration
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "live\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.Error(w, "identity account and session backend not provisioned", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("GET /api/identity/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwks)
	})
	return mux, nil
}

// StandaloneHTTPServer never accepts a host, port or network flag: no
// production-facing listener, tunnel, cross-origin API or cookie handler.
func StandaloneHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{Addr: LocalAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
}
