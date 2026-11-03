package websession

import (
	"context"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/admininventory"
	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

// AdminInventoryPath is a same-origin-only staging API. The runtime mounts it
// only when an independent inventory principal is explicitly configured.
const AdminInventoryPath = "/api/identity/admin/accounts"

type adminInventoryReader func(context.Context, string, string, int) (admininventory.Page, error)
type adminInventoryHandler struct {
	read   adminInventoryReader
	limits limiter
}

// NewStagingAdminInventoryHandler binds authentication and auditing to the
// server-side issuer. The requesting browser can never provide its role or ID.
func NewStagingAdminInventoryHandler(reader *issuance.StagingAdminInventoryReader) (http.Handler, error) {
	if reader == nil {
		return nil, issuance.ErrDenied
	}
	return &adminInventoryHandler{read: reader.StagingAdminInventory}, nil
}

func (h *adminInventoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if h == nil || h.read == nil || r.TLS == nil || r.Host != stagingHost || r.URL.Path != AdminInventoryPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != StagingOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
		http.Error(w, "request denied", http.StatusForbidden)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !h.limits.allow(peer, false, time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "request limit", http.StatusTooManyRequests)
		return
	}
	var body struct {
		After string `json:"after"`
		Limit int    `json:"limit"`
	}
	if !decode(w, r, &body) {
		return
	}
	handle, ok := readCookie(r)
	if !ok {
		failure(w, issuance.ErrDenied)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	page, err := h.read(ctx, handle, body.After, body.Limit)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(page)
}
