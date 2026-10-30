package websession

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This fixture serves the real Identity UI/API and disposable Mongo. Product
// pages are explicitly synthetic CORS clients, not the Chronicles application.
func TestChromiumCentralAccountJourney(t *testing.T) {
	if os.Getenv("IDENTITY_BROWSER_TEST") != "1" {
		t.Skip("explicit local browser test not configured")
	}
	f := setupMode(t, true)
	listener, err := net.Listen("tcp", "127.0.0.1:19443")
	if err != nil {
		t.Fatal("browser fixture port unavailable", err)
	}
	edge := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == stagingHost {
			f.h.ServeHTTP(w, r)
			return
		}
		if _, allowed := consumers["https://"+r.Host]; !allowed {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><title>Synthetic consumer</title><body><p id="status">Synthetic consumer fixture</p><script>
fetch('https://id-staging.shadowops.dpdns.org/api/identity/token', {method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{}'})
 .then(async r => {window.fixtureStatus=r.status;if(r.ok)window.fixtureToken=(await r.json()).token;document.body.dataset.done='true';})
 .catch(() => {window.fixtureStatus=0;document.body.dataset.done='true';});
</script></body></html>`))
	}))
	edge.Listener.Close()
	edge.Listener = listener
	edge.StartTLS()
	defer edge.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "testdata/browser.cjs")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Chromium browser journey failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}
