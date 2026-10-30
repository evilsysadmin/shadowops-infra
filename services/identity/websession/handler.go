// Package websession implements the staging browser session transport. It is
// opt-in: the existing localhost bootstrap does not instantiate this handler.
package websession

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

const (
	StagingOrigin = "https://id-staging.shadowops.dpdns.org"
	stagingHost   = "id-staging.shadowops.dpdns.org"
	// __Host- prevents a sibling application from planting a Domain cookie
	// with the same name. It requires Secure, Path=/ and no Domain attribute.
	CookieName = "__Host-shadowops_sso_staging"
)

var consumers = map[string]issuance.Application{
	"https://staging.chess-studio.shadowops.dpdns.org": issuance.ChessStudio,
	"https://staging.chronicles.shadowops.dpdns.org":   issuance.Chronicles,
	"https://staging.cka.shadowops.dpdns.org":          issuance.CKASimulator,
}

type Handler struct {
	issuer  *issuance.Issuer
	signers map[issuance.Application]*issuance.StagingAppSigner
	public  []byte
	limits  limiter
	kdf     chan struct{}
}

// NewStagingHandler requires a real staging issuer, an independent staging
// signing seed, and end-to-end TLS. No proxy header can assert TLS, host or IP.
// Origins are pinned here; an audience/subject from a token request is never
// trusted. No registration, legacy activation or authorization is performed.
func NewStagingHandler(issuer *issuance.Issuer, seed []byte) (*Handler, error) {
	h := &Handler{issuer: issuer, signers: make(map[issuance.Application]*issuance.StagingAppSigner), kdf: make(chan struct{}, 2)}
	for _, app := range consumers {
		signer, err := issuance.NewStagingAppSigner(issuer, seed, app)
		if err != nil {
			return nil, issuance.ErrDenied
		}
		h.signers[app] = signer
		if h.public == nil {
			h.public, err = signer.JWKS()
			if err != nil {
				return nil, issuance.ErrDenied
			}
		}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Vary", "Origin")
	if r.TLS == nil || r.Host != stagingHost {
		http.Error(w, "staging HTTPS identity host required", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/api/identity/jwks" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(h.public)
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		http.Error(w, "browser SSO rollout not provisioned", http.StatusServiceUnavailable)
		return
	}
	if !sessionPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	// A mandatory exact Origin and JSON-only POSTs protect cookie mutations,
	// including login CSRF. Fetch Metadata and SameSite are defense in depth.
	origin := r.Header.Get("Origin")
	app, product := consumers[origin]
	if len(r.Header.Values("Origin")) != 1 || (origin != StagingOrigin && !product) ||
		r.Header.Get("Sec-Fetch-Site") == "cross-site" ||
		(r.URL.Path == "/api/identity/login" && origin != StagingOrigin) ||
		(r.URL.Path == "/api/identity/token" && !product) {
		http.Error(w, "origin denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	if r.Method == http.MethodOptions {
		if r.Header.Get("Access-Control-Request-Method") != "POST" ||
			!strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers")), "content-type") {
			http.Error(w, "preflight denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
		http.Error(w, "invalid session request", http.StatusBadRequest)
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !h.limits.allow(peer, r.URL.Path == "/api/identity/login", time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "request limit", http.StatusTooManyRequests)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if r.URL.Path == "/api/identity/login" {
		var body struct {
			Subject  string `json:"subject"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		select {
		case h.kdf <- struct{}{}:
			defer func() { <-h.kdf }()
		default:
			w.Header().Set("Retry-After", "60")
			http.Error(w, "request limit", http.StatusTooManyRequests)
			return
		}
		handle, err := h.issuer.Issue(ctx, body.Subject, body.Password)
		if err != nil {
			failure(w, err)
			return
		}
		setCookie(w, handle, false)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var empty struct{}
	if !decode(w, r, &empty) {
		return
	}
	handle, ok := readCookie(r)
	if !ok {
		failure(w, issuance.ErrDenied)
		return
	}
	switch r.URL.Path {
	case "/api/identity/token":
		token, err := h.signers[app].IssueToken(ctx, handle)
		if err != nil {
			failure(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Token string `json:"token"`
		}{Token: token})
	case "/api/identity/refresh":
		next, err := h.issuer.Refresh(ctx, handle)
		if err != nil {
			// A losing concurrent rotation must not clear the winner's cookie.
			failure(w, err)
			return
		}
		setCookie(w, next, false)
		w.WriteHeader(http.StatusNoContent)
	case "/api/identity/logout":
		if err := h.issuer.Logout(ctx, handle); err != nil {
			failure(w, err)
			return
		}
		// Clear only after server-side revocation has committed.
		setCookie(w, "", true)
		w.WriteHeader(http.StatusNoContent)
	}
}

func sessionPath(path string) bool {
	switch path {
	case "/api/identity/login", "/api/identity/token", "/api/identity/refresh", "/api/identity/logout":
		return true
	}
	return false
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	data, err := io.ReadAll(r.Body)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 || strings.TrimSpace(string(data))[0] != '{' {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return false
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err == nil {
		var trailing any
		if d.Decode(&trailing) == io.EOF {
			return true
		}
	}
	http.Error(w, "invalid JSON request", http.StatusBadRequest)
	return false
}

func readCookie(r *http.Request) (string, bool) {
	var handle string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == CookieName {
			count++
			handle = c.Value
		}
	}
	return handle, count == 1 && len(handle) == 47
}

func setCookie(w http.ResponseWriter, value string, clear bool) {
	c := &http.Cookie{Name: CookieName, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	// Browser-session cookie: Mongo enforces the original 24h absolute expiry;
	// refresh cannot extend it, nor can a persistent browser cookie suggest so.
	if clear {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0).UTC()
	}
	http.SetCookie(w, c)
}

func failure(w http.ResponseWriter, err error) {
	if errors.Is(err, issuance.ErrDenied) {
		http.Error(w, "authentication denied", http.StatusUnauthorized)
	} else {
		http.Error(w, "identity unavailable", http.StatusServiceUnavailable)
	}
}

type bucket struct {
	login, total int
	start        time.Time
}

// Fixed, bounded per-process abuse limits. RemoteAddr is the socket peer;
// X-Forwarded-For is intentionally ignored. A deployment behind a proxy needs
// separate authenticated proxy and distributed abuse-control design.
type limiter struct {
	mu     sync.Mutex
	peers  map[string]bucket
	global bucket
}

func (l *limiter) allow(peer string, login bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peers == nil {
		l.peers = make(map[string]bucket)
	}
	if now.Sub(l.global.start) >= time.Minute {
		l.global = bucket{start: now}
		for key, b := range l.peers {
			if now.Sub(b.start) >= time.Minute {
				delete(l.peers, key)
			}
		}
	}
	b, exists := l.peers[peer]
	if !exists && len(l.peers) >= 1024 {
		return false
	}
	if now.Sub(b.start) >= time.Minute {
		b = bucket{start: now}
	}
	if b.total >= 120 || l.global.total >= 600 || (login && (b.login >= 10 || l.global.login >= 60)) {
		return false
	}
	b.total++
	l.global.total++
	if login {
		b.login++
		l.global.login++
	}
	l.peers[peer] = b
	return true
}
