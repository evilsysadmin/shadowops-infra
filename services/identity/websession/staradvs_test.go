package websession

import (
	"net/http"
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

func TestStarAdventuresLogoutConfirmationIsGetOnlyAndPinned(t *testing.T) {
	h := &Handler{enabled: map[issuance.Application]bool{issuance.StarAdventures: true}}
	req := httptest.NewRequest(http.MethodGet, StagingOrigin+"/logout?app=staradvs", nil)
	res := httptest.NewRecorder()
	if !h.page(res, req) || res.Code != http.StatusOK {
		t.Fatalf("logout confirmation failed: %d", res.Code)
	}
	body := res.Body.String()
	for _, required := range []string{
		"Cerrar sesión", "Confirmar cierre de sesión",
		"id=\"logout-form\"", "data-return-url=\"https://staging.staradvs.shadowops.dpdns.org/\"",
		"/assets/staradvs-logout.js", "Volver a Star Adventures",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("missing logout form field %q", required)
		}
	}
	if strings.Contains(body, "token=") || strings.Contains(body, "http://") ||
		res.Header().Get("Set-Cookie") != "" ||
		!strings.Contains(res.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("GET logout must not revoke, set cookies, or issue tokens")
	}
	scriptReq := httptest.NewRequest(http.MethodGet, StagingOrigin+"/assets/staradvs-logout.js", nil)
	scriptRes := httptest.NewRecorder()
	if !h.page(scriptRes, scriptReq) || scriptRes.Code != 200 ||
		!strings.Contains(scriptRes.Header().Get("Content-Type"), "javascript") {
		t.Fatal("IdP logout script not served same-origin")
	}
	script := scriptRes.Body.String()
	for _, marker := range []string{
		"form.addEventListener('submit'",
		"fetch('/api/identity/logout'",
		"method: 'POST'",
		"credentials: 'same-origin'",
		"redirect: 'error'",
		"response.status !== 204",
		"window.location.replace(document.body.dataset.returnUrl)",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("missing safe logout behavior %q", marker)
		}
	}
	if strings.Contains(script, "fetch('https://") || strings.Contains(script, "localStorage") ||
		strings.Contains(script, "sessionStorage") {
		t.Fatal("logout must remain on IdP with no browser token persistence")
	}
}

func TestStarAdventuresLogoutRejectsOtherAudiencesAndOpenRedirects(t *testing.T) {
	enabled := &Handler{enabled: map[issuance.Application]bool{issuance.StarAdventures: true}}
	for _, query := range []string{
		"", "?app=snooker", "?app=bridgesquad", "?app=staradvs&next=https://evil.test",
		"?app=staradvs&app=staradvs", "?next=https://evil.test", "?app=%73taradvs",
	} {
		t.Run(query, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, StagingOrigin+"/logout"+query, nil)
			res := httptest.NewRecorder()
			if !enabled.page(res, req) || res.Code != 400 ||
				res.Header().Get("Set-Cookie") != "" ||
				strings.Contains(res.Body.String(), "data-return-url=") {
				t.Fatalf("untrusted logout target accepted: query=%q status=%d", query, res.Code)
			}
		})
	}
	for _, h := range []*Handler{
		{enabled: map[issuance.Application]bool{issuance.StarAdventures: false}},
		{enabled: map[issuance.Application]bool{issuance.Snooker: true}},
		{},
	} {
		req := httptest.NewRequest(http.MethodGet, StagingOrigin+"/logout?app=staradvs", nil)
		res := httptest.NewRecorder()
		if !h.page(res, req) || res.Code != 400 {
			t.Fatal("unprovisioned audience accepted logout")
		}
	}
	req := httptest.NewRequest(http.MethodPost, StagingOrigin+"/logout?app=staradvs", nil)
	res := httptest.NewRecorder()
	if !enabled.page(res, req) || res.Code != http.StatusMethodNotAllowed ||
		res.Header().Get("Set-Cookie") != "" {
		t.Fatal("POST /logout page must not mutate IdP sessions")
	}
}
