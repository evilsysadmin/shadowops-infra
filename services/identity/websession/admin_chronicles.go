package websession

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

const AdminChroniclesPath = "/api/identity/admin/chronicles"
const chroniclesRosterURL = "https://chronicles-api-staging.shadowops.dpdns.org/api/chronicles/admin/users"

var chroniclesProfile = regexp.MustCompile(`^shadowops:staging:([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$`)

type chroniclesActivity struct {
	Subject          string `json:"subject"`
	LastActivity     string `json:"lastActivity,omitempty"`
	Online           bool   `json:"online"`
	MapID            string `json:"mapId,omitempty"`
	SavedAt          string `json:"savedAt,omitempty"`
	RunStatus        string `json:"runStatus,omitempty"`
	ActiveQuests     int    `json:"activeQuests,omitempty"`
	CompletedQuests  int    `json:"completedQuests,omitempty"`
	SavedExpeditions int64  `json:"savedExpeditions,omitempty"`
}

type chroniclesAdminHandler struct {
	read   adminInventoryReader
	sign   func(context.Context, string) (string, error)
	client *http.Client
	limits limiter
}

// NewStagingAdminChroniclesHandler requires both an Identity administrator
// session and independent Chronicles admin authorization. Tokens stay server-side.
func (s *Service) NewStagingAdminChroniclesHandler(reader *issuance.StagingAdminInventoryReader) (http.Handler, error) {
	if s == nil || s.browser == nil || !s.browser.enabled[issuance.Chronicles] || s.browser.signers[issuance.Chronicles] == nil || reader == nil {
		return nil, issuance.ErrDenied
	}
	return &chroniclesAdminHandler{read: reader.StagingAdminInventory, sign: s.browser.signers[issuance.Chronicles].IssueToken,
		client: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (h *chroniclesAdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h == nil || h.read == nil || h.sign == nil || h.client == nil || r.TLS == nil || r.Host != stagingHost || r.URL.Path != AdminChroniclesPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return
	}
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != StagingOrigin || r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "request denied", http.StatusForbidden)
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(peer) == nil || !h.limits.allow(peer, false, time.Now()) {
		http.Error(w, "request limit", http.StatusTooManyRequests)
		return
	}
	var body struct {
		After string `json:"after"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.After) > 64 || strings.TrimSpace(body.After) != body.After || strings.ContainsAny(body.After, "\r\n\x00") {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}
	handle, ok := readCookie(r)
	if !ok {
		failure(w, issuance.ErrDenied)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err = h.read(ctx, handle, "", 1); err != nil {
		failure(w, err)
		return
	}
	token, err := h.sign(ctx, handle)
	if err != nil {
		failure(w, err)
		return
	}
	endpoint := chroniclesRosterURL
	if body.After != "" {
		endpoint += "?after=" + url.QueryEscape(body.After)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := h.client.Do(request)
	if err != nil {
		http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		http.Error(w, "chronicles admin required", http.StatusForbidden)
		return
	}
	if response.StatusCode != http.StatusOK {
		http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 262145))
	if err != nil || len(raw) > 262144 {
		http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
		return
	}
	var page struct {
		Users []struct {
			Username         string `json:"username"`
			LastActivity     string `json:"lastActivity"`
			Online           bool   `json:"online"`
			MapID            string `json:"mapId"`
			SavedAt          string `json:"savedAt"`
			RunStatus        string `json:"runStatus"`
			ActiveQuests     int    `json:"activeQuests"`
			CompletedQuests  int    `json:"completedQuests"`
			SavedExpeditions int64  `json:"savedExpeditions"`
		} `json:"users"`
		NextAfter string `json:"nextAfter"`
	}
	if json.Unmarshal(raw, &page) != nil || len(page.Users) > 40 || len(page.NextAfter) > 64 {
		http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
		return
	}
	items := make([]chroniclesActivity, 0, len(page.Users))
	for _, u := range page.Users {
		m := chroniclesProfile.FindStringSubmatch(u.Username)
		if m == nil {
			continue
		}
		if len(u.LastActivity) > 64 || len(u.SavedAt) > 64 || len(u.MapID) > 128 || len(u.RunStatus) > 64 || u.ActiveQuests < 0 || u.CompletedQuests < 0 || u.SavedExpeditions < 0 {
			http.Error(w, "activity unavailable", http.StatusServiceUnavailable)
			return
		}
		items = append(items, chroniclesActivity{m[1], u.LastActivity, u.Online, u.MapID, u.SavedAt, u.RunStatus, u.ActiveQuests, u.CompletedQuests, u.SavedExpeditions})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Accounts []chroniclesActivity `json:"accounts"`
		Next     string               `json:"next,omitempty"`
	}{items, page.NextAfter})
}
