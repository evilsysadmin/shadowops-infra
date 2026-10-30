package websession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

const FreshnessPath = "/api/identity/freshness"

// ConsumerCredentials are independent 256-bit soc1_ secrets, provisioned by a
// trusted operator per application. They are not signing keys, user passwords,
// cookies or access tokens. Values never come from a browser or request body.
type ConsumerCredentials map[issuance.Application]string

type Service struct {
	browser  *Handler
	checkers map[[32]byte]*issuance.StagingAppFreshness
	limits   limiter
}

// NewStagingServiceHandler enables the browser flow and an authenticated
// server-to-server freshness endpoint. An explicit nonempty credential map is
// required. Each credential is bound to one audience at construction; only a
// digest remains in the handler, and duplicate/cross-audience secrets fail.
// This does not provision credentials, change a consumer or deploy a listener.
func NewStagingServiceHandler(ctx context.Context, issuer *issuance.Issuer, seed []byte, credentials ConsumerCredentials) (*Service, error) {
	if len(credentials) == 0 || len(credentials) > len(consumers) {
		return nil, issuance.ErrDenied
	}
	s := &Service{checkers: make(map[[32]byte]*issuance.StagingAppFreshness)}
	for app, credential := range credentials {
		digest, valid := consumerDigest(credential)
		if !valid || s.checkers[digest] != nil {
			return nil, issuance.ErrDenied
		}
		checker, err := issuance.NewStagingAppFreshness(issuer, app)
		if err != nil {
			return nil, issuance.ErrDenied
		}
		s.checkers[digest] = checker
	}
	var err error
	s.browser, err = NewStagingBrowserHandler(ctx, issuer, seed)
	if err != nil {
		return nil, err
	}
	// Activate only explicitly registered consumers. Candidate origins and
	// login return targets for other projects remain unavailable.
	s.browser.enabled = make(map[issuance.Application]bool)
	for app := range credentials {
		s.browser.enabled[app] = true
	}
	return s, nil
}

func consumerDigest(credential string) ([32]byte, bool) {
	if len(credential) != 48 || !strings.HasPrefix(credential, "soc1_") {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(credential[5:])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != credential[5:] {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte("shadowops-consumer-v1:staging:" + credential)), true
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != FreshnessPath {
		s.browser.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS == nil || r.Host != stagingHost || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 {
		http.Error(w, "service transport required", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !s.limits.allow(peer, false, time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "request limit", http.StatusTooManyRequests)
		return
	}
	credential, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest, canonical := consumerDigest(credential)
	if len(r.Header.Values("Authorization")) != 1 || !bearer || !canonical || s.checkers[digest] == nil {
		failure(w, issuance.ErrDenied)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" || r.URL.RawQuery != "" {
		http.Error(w, "invalid service request", http.StatusBadRequest)
		return
	}
	var body struct {
		Subject        string `json:"subject"`
		SessionVersion int64  `json:"session_version"`
		TokenJTI       string `json:"token_jti"`
	}
	if !decode(w, r, &body) {
		return
	}
	// The authenticated service selects the checker. A body cannot choose an
	// audience, issuer, state flags or timestamp. Each request rereads and
	// transactionally fences live account/session/token state, with no cache.
	evidence, err := s.checkers[digest].Check(r.Context(), body.Subject, body.SessionVersion, body.TokenJTI)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(evidence)
}
