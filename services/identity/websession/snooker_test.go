package websession

import (
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

func TestSnookerLoginPinnedAndDeniedUnlessEnabled(t *testing.T) {
    const origin = "https://staging.snooker.shadowops.dpdns.org"
    for _, enabled := range []bool{false, true} {
        h := &Handler{enabled: map[issuance.Application]bool{issuance.Snooker: enabled}}
        request := httptest.NewRequest("GET", StagingOrigin+"/login?app=snooker", nil)
        response := httptest.NewRecorder()
        if !h.page(response, request) { t.Fatal("Snooker login route unhandled") }
        if !enabled && response.Code != 400 {
            t.Fatalf("Unprovisioned Snooker login accepted: %d", response.Code)
        }
        if enabled && (response.Code != 200 ||
           !strings.Contains(response.Body.String(), origin+"/?shadowops=central") ||
           strings.Contains(response.Body.String(), "token=")) {
            t.Fatal("Snooker login must be pinned, without tokens in URLs")
        }
        cors := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
        cors.Header.Set("Origin", origin)
        cors.Header.Set("Access-Control-Request-Method", "POST")
        cors.Header.Set("Access-Control-Request-Headers", "content-type")
        result := httptest.NewRecorder()
        h.ServeHTTP(result, cors)
        if enabled && (result.Code != 204 || result.Header().Get("Access-Control-Allow-Origin") != origin) {
            t.Fatal("Explicit Snooker consumer preflight not pinned")
        }
        if !enabled && (result.Code != 403 || result.Header().Get("Access-Control-Allow-Origin") != "") {
            t.Fatal("Unprovisioned Snooker origin must not receive CORS access")
        }
    }
}

func TestSnookerDoesNotEnableFootballOrForeignOrigins(t *testing.T) {
    h := &Handler{enabled: map[issuance.Application]bool{issuance.Snooker: true}}
    for _, foreign := range []string{
        "https://staging.football.shadowops.dpdns.org",
        "https://staging.snooker.shadowops.dpdns.org.evil.test",
        "http://staging.snooker.shadowops.dpdns.org",
    } {
        cors := httptest.NewRequest("OPTIONS", StagingOrigin+"/api/identity/token", nil)
        cors.Header.Set("Origin", foreign)
        cors.Header.Set("Access-Control-Request-Method", "POST")
        cors.Header.Set("Access-Control-Request-Headers", "content-type")
        response := httptest.NewRecorder()
        h.ServeHTTP(response, cors)
        if response.Code != 403 || response.Header().Get("Access-Control-Allow-Origin") != "" {
            t.Fatalf("Foreign origin admitted: %q", foreign)
        }
    }
    login := httptest.NewRequest("GET", StagingOrigin+"/login?app=football", nil)
    response := httptest.NewRecorder()
    if !h.page(response, login) || response.Code != 400 {
        t.Fatal("Snooker registration must never activate Football")
    }
}
