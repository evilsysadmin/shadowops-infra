package websession

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestStarAdventuresLoginRequiresExplicitStagingConsumer(t *testing.T) {
	const origin = "https://staging.staradvs.shadowops.dpdns.org"
	for _, enabled := range []bool{false, true} {
		h := &Handler{enabled: map[issuance.Application]bool{issuance.StarAdventures: enabled}}
		request := httptest.NewRequest("GET", StagingOrigin+"/login?app=staradvs", nil)
		response := httptest.NewRecorder()
		if !h.page(response, request) {
			t.Fatal("Star Adventures login unhandled")
		}
		if !enabled && response.Code != 400 {
			t.Fatal("unprovisioned Star Adventures audience was admitted")
		}
		if enabled && (response.Code != 200 ||
			!strings.Contains(response.Body.String(), origin+"/?shadowops=central") ||
			strings.Contains(response.Body.String(), "token=")) {
			t.Fatal("Star Adventures return origin must be pinned and token-free")
		}
		cors := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
		cors.Header.Set("Origin", origin)
		cors.Header.Set("Access-Control-Request-Method", "POST")
		cors.Header.Set("Access-Control-Request-Headers", "content-type")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, cors)
		if enabled && (out.Code != 204 || out.Header().Get("Access-Control-Allow-Origin") != origin) {
			t.Fatal("explicit Star Adventures origin not admitted")
		}
		if !enabled && (out.Code != 403 || out.Header().Get("Access-Control-Allow-Origin") != "") {
			t.Fatal("unprovisioned Star Adventures origin must not receive CORS access")
		}
	}
}

func TestStarAdventuresCannotReuseSnookerOrForeignStagingOrigin(t *testing.T) {
	h := &Handler{enabled: map[issuance.Application]bool{issuance.StarAdventures: true}}
	for _, foreign := range []string{
		"https://staging.snooker.shadowops.dpdns.org",
		"https://staging.staradvs.shadowops.dpdns.org.attacker.invalid",
		"http://staging.staradvs.shadowops.dpdns.org",
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
	request := httptest.NewRequest("GET", StagingOrigin+"/login?app=snooker", nil)
	response := httptest.NewRecorder()
	if !h.page(response, request) || response.Code != 400 {
		t.Fatal("Star Adventures must not activate Snooker")
	}
}
