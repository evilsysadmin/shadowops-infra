package production

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "io"
    "net"
    "net/http"
    "net/http/httptest"
    "os"
    "os/exec"
    "testing"
    "time"
)

// The production login/JWT/opaque session backend is genuine, with a
// disposable localhost Mongo replica. The Bridge Squad document is a small
// synthetic CORS consumer, NOT the deployed game or Cloudflare Worker.
// Browsers exercise real HTTPS origins, host-only cookies and CORS without
// touching public DNS, Mongo, Cloudflare or production credentials.
func TestChromiumProductionBridgeSquadJourney(t *testing.T) {
    if os.Getenv("IDENTITY_PRODUCTION_BROWSER_TEST") != "1" {
        t.Skip("opt-in isolated production browser journey not configured")
    }
    accounts, signer, _, _ := productionTokenFixture(t)
    h, err := NewProductionBrowserHandler(accounts, signer, syntheticProof())
    if err != nil { t.Fatal(err) }
    cert, err := fixture(t).Validate(time.Now().UTC())
    if err != nil { t.Fatal(err) }
    prod, err := newProductionHTTPServer(cert, accounts.client, h)
    if err != nil { t.Fatal(err) }

    const bridgeHost = "bridgesquad.shadowops.dpdns.org"
    const consumerPage = `<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Synthetic Bridge Squad CORS consumer</title>
<body><h1>Consumer de prueba</h1><p id="status">Validando sesión</p>
<script>
(async () => {
 try {
  const response = await fetch('https://id.shadowops.dpdns.org/api/identity/token', {
   method:'POST',credentials:'include',cache:'no-store',redirect:'error',
   headers:{'Content-Type':'application/json'},body:'{}'
  });
  window.fixtureStatus = response.status;
  if (response.ok) window.fixtureToken = (await response.json()).token;
 } catch (error) { window.fixtureStatus = 0; }
 finally { document.body.dataset.done = 'true'; }
})();
</script></body></html>`

    routes := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        switch req.Host {
        case Host:
            prod.Handler.ServeHTTP(w, req)
        case bridgeHost:
            w.Header().Set("Cache-Control", "no-store")
            if req.URL.Path == "/api/fixture-check" && req.Method == http.MethodPost &&
               req.Header.Get("Origin") == Origin &&
               req.Header.Get("Content-Type") == "application/json" {
                raw, readErr := io.ReadAll(io.LimitReader(req.Body, 8193))
                if readErr != nil || len(raw) > 8192 { http.Error(w, "invalid", 400); return }
                var body struct { Token string `json:"token"` }
                if json.Unmarshal(raw, &body) != nil || body.Token == "" {
                    http.Error(w, "invalid", 400); return
                }
                if _, err := signer.Check(req.Context(), body.Token); err != nil {
                    http.Error(w, "denied", http.StatusUnauthorized); return
                }
                w.WriteHeader(http.StatusNoContent)
                return
            }
            if req.Method != http.MethodGet || (req.URL.Path != "/" && req.URL.Path != "/index.html") {
                http.NotFound(w, req); return
            }
            w.Header().Set("Content-Type", "text/html; charset=utf-8")
            _, _ = io.WriteString(w, consumerPage)
        default:
            http.NotFound(w, req)
        }
    })
    listener, err := net.Listen("tcp", "127.0.0.1:19444")
    if err != nil { t.Fatal("production browser fixture port unavailable:", err) }
    server := httptest.NewUnstartedServer(routes)
    _ = server.Listener.Close()
    server.Listener = listener
    server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: prod.TLSConfig.Certificates}
    server.StartTLS()
    defer server.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, "node", "testdata/production_browser.cjs")
    out, err := cmd.CombinedOutput()
    if err != nil {
        t.Fatalf("production Chromium journey failed: %v\n%s", err, out)
    }
    t.Log(string(out))
}
