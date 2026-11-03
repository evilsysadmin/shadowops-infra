package websession

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestPawnActionLoginPinnedAndDisabledWithoutExplicitConsumer(t *testing.T) {
	const origin = "https://staging.pawnaction.shadowops.dpdns.org"
	for _, enabled := range []bool{false, true} {
		h := &Handler{enabled: map[issuance.Application]bool{issuance.PawnAction: enabled}}
		r := httptest.NewRequest("GET", StagingOrigin+"/login?app=pawn-action", nil)
		w := httptest.NewRecorder()
		if !h.page(w, r) {
			t.Fatal("Pawn Action login route unhandled")
		}
		if !enabled {
			if w.Code != 400 {
				t.Fatalf("unprovisioned consumer admitted: %d", w.Code)
			}
		} else if w.Code != 200 || !strings.Contains(w.Body.String(), origin+"/?shadowops=central") ||
			strings.Contains(w.Body.String(), "token=") {
			t.Fatal("Pawn Action login return must be pinned and credential-free")
		}
		preflight := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
		preflight.Header.Set("Origin", origin)
		preflight.Header.Set("Access-Control-Request-Method", "POST")
		preflight.Header.Set("Access-Control-Request-Headers", "content-type")
		cw := httptest.NewRecorder()
		h.ServeHTTP(cw, preflight)
		if enabled && (cw.Code != 204 || cw.Header().Get("Access-Control-Allow-Origin") != origin) {
			t.Fatal("explicit consumer preflight not origin bound")
		}
		if !enabled && (cw.Code != 403 || cw.Header().Get("Access-Control-Allow-Origin") != "") {
			t.Fatal("unprovisioned consumer obtained CORS access")
		}
	}
}

func TestPawnActionCannotUseFootballProofOrForeignOrigin(t *testing.T) {
	const origin = "https://staging.pawnaction.shadowops.dpdns.org"
	h := &Handler{enabled: map[issuance.Application]bool{issuance.PawnAction: true}}
	for _, other := range []string{"https://staging.football.shadowops.dpdns.org",
		"https://staging.pawnaction.shadowops.dpdns.org.evil.test", "http://staging.pawnaction.shadowops.dpdns.org"} {
		r := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
		r.Header.Set("Origin", other)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "content-type")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("foreign origin admitted: %q", other)
		}
	}
	r := httptest.NewRequest("GET", StagingOrigin+"/login?app=football", nil)
	w := httptest.NewRecorder()
	if !h.page(w, r) || w.Code != 400 {
		t.Fatal("Pawn Action access must not activate Football")
	}
	_ = origin
}
