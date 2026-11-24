package websession

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestBridgeSquadLoginRequiresExplicitStagingConsumer(t *testing.T) {
	const origin = "https://staging.bridgesquad.shadowops.dpdns.org"
	for _, enabled := range []bool{false, true} {
		h := &Handler{enabled: map[issuance.Application]bool{issuance.BridgeSquad: enabled}}
		request := httptest.NewRequest("GET", StagingOrigin+"/login?app=bridgesquad", nil)
		response := httptest.NewRecorder()
		if !h.page(response, request) {
			t.Fatal("Bridge Squad login unhandled")
		}
		if !enabled && response.Code != 400 {
			t.Fatal("unprovisioned Bridge Squad audience was admitted")
		}
		if enabled && (response.Code != 200 ||
			!strings.Contains(response.Body.String(), origin+"/?shadowops=central") ||
			strings.Contains(response.Body.String(), "token=")) {
			t.Fatal("Bridge Squad return origin must be pinned and token-free")
		}
		cors := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
		cors.Header.Set("Origin", origin)
		cors.Header.Set("Access-Control-Request-Method", "POST")
		cors.Header.Set("Access-Control-Request-Headers", "content-type")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, cors)
		if enabled && (out.Code != 204 || out.Header().Get("Access-Control-Allow-Origin") != origin) {
			t.Fatal("explicit Bridge Squad origin not admitted")
		}
		if !enabled && (out.Code != 403 || out.Header().Get("Access-Control-Allow-Origin") != "") {
			t.Fatal("unprovisioned Bridge Squad origin must not receive CORS access")
		}
	}
}

func TestBridgeSquadCannotReuseStarAdventuresOrForeignStagingOrigin(t *testing.T) {
	h := &Handler{enabled: map[issuance.Application]bool{issuance.BridgeSquad: true, issuance.StarAdventures: false}}
	for _, foreign := range []string{
		"https://staging.staradvs.shadowops.dpdns.org",
		"https://bridgesquad.shadowops.dpdns.org",
		"https://staging.bridgesquad.shadowops.dpdns.org.attacker.invalid",
		"http://staging.bridgesquad.shadowops.dpdns.org",
	} {
		request := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
		request.Header.Set("Origin", foreign)
		request.Header.Set("Access-Control-Request-Method", "POST")
		request.Header.Set("Access-Control-Request-Headers", "content-type")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != 403 || response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("foreign origin admitted: %q", foreign)
		}
	}
	request := httptest.NewRequest("GET", StagingOrigin+"/login?app=staradvs", nil)
	response := httptest.NewRecorder()
	if !h.page(response, request) || response.Code != 400 {
		t.Fatal("Bridge Squad must not activate Star Adventures")
	}
}
