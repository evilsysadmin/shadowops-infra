package websession

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestSnookerLoginHasHumanNameAndPinnedReturnURL(t *testing.T) {
	h := &Handler{enabled: map[issuance.Application]bool{issuance.Snooker: true}}
	req := httptest.NewRequest(http.MethodGet,
		StagingOrigin+"/login?app=snooker", nil)
	w := httptest.NewRecorder()
	if !h.page(w, req) {
		t.Fatal("staging login route not handled")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("Snooker login returned %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, wanted := range []string{
		"Continúa a <strong>Snooker of Matthias</strong>",
		"Volver a Snooker of Matthias",
		"https://staging.snooker.shadowops.dpdns.org/?shadowops=central",
	} {
		if !strings.Contains(body, wanted) {
			t.Fatalf("Snooker login missing %q", wanted)
		}
	}
	if strings.Contains(body, "staging.football.shadowops.dpdns.org") {
		t.Fatal("Snooker login contains a foreign return origin")
	}
}

func TestSnookerLoginMustRemainDisabledWithoutConsumerOptIn(t *testing.T) {
	for _, tc := range []struct {
		label	string
		enabled	map[issuance.Application]bool
	}{
		{"disabled", map[issuance.Application]bool{issuance.Snooker: false}},
		{"missing", map[issuance.Application]bool{issuance.Football: true}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			h := &Handler{enabled: tc.enabled}
			req := httptest.NewRequest(http.MethodGet,
				StagingOrigin+"/login?app=snooker", nil)
			w := httptest.NewRecorder()
			handled := h.page(w, req)
			if !handled || w.Code != http.StatusBadRequest {
				t.Fatalf("inactive Snooker accepted: handled=%v status=%d", handled, w.Code)
			}
			if strings.Contains(w.Body.String(), "shadowops=central") {
				t.Fatal("inactive Snooker exposed a usable return URL")
			}
		})
	}
}
