// Staging bootstrap is intentionally NOT a public IdP. The binary serves
// only localhost health/JWKS and deliberately never becomes ready for auth.
package main

import (
	"github.com/evilsysadmin/shadowops-infra/services/identity/runtime"
	"log"
	"net/http"
	"os"
)

func main() {
	seed, err := runtime.LoadStagingSeed(os.Getenv("IDENTITY_ENVIRONMENT"), os.Getenv("IDENTITY_STAGING_SEED_FILE"))
	if err != nil {
		log.Fatal("identity bootstrap: invalid environment or protected seed file")
	}
	handler, err := runtime.NewStagingHandler("staging", seed)
	clear(seed)
	if err != nil {
		log.Fatal("identity bootstrap: unsafe configuration")
	}
	server := runtime.StandaloneHTTPServer(handler)
	log.Printf("identity bootstrap: localhost only, not ready for user authentication")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("identity bootstrap server terminated")
	}
}
