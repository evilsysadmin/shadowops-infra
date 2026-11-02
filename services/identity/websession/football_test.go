package websession

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestFootballReturnIsPinnedAndRequiresExplicitConsumerActivation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		h := &Handler{enabled: map[issuance.Application]bool{issuance.Football: enabled}}
		request := httptest.NewRequest("GET", StagingOrigin+"/login?app=football", nil)
		response := httptest.NewRecorder()
		if !h.page(response, request) {
			t.Fatal("Football login route not handled")
		}
		if !enabled {
			if response.Code != 400 {
				t.Fatal("unprovisioned Football was admitted")
			}
			continue
		}
		if response.Code != 200 || !strings.Contains(response.Body.String(), "https://staging.football.shadowops.dpdns.org/?shadowops=central") {
			t.Fatal("Football return origin was not pinned")
		}
		if strings.Contains(response.Body.String(), "token=") {
			t.Fatal("login return included a credential")
		}
	}
}
