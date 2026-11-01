// service-staging is the explicitly configured TLS staging IdP. The older
// cmd/staging remains an unwired health/JWKS bootstrap.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	identityruntime "github.com/evilsysadmin/shadowops-infra/services/identity/runtime"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if !healthcheck() {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Fatal("invalid Identity service command")
	}
	cfg, err := identityruntime.LoadServiceConfig(os.Getenv("IDENTITY_STAGING_CONFIG_FILE"))
	if err != nil {
		log.Fatal("invalid private staging Identity configuration")
	}
	start, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	service, err := identityruntime.NewStagingService(start, cfg)
	cancel()
	if err != nil {
		log.Fatal("staging Identity initialization denied")
	}
	// Avoid retaining extra operator-config references after construction.
	cfg.AdminAliasCredential = ""
	cfg.SigningSeed = ""
	cfg.MongoURI = ""
	cfg.TLSPrivateKey = ""
	cfg.Consumers = nil
	if port := os.Getenv("IDENTITY_INTERNAL_PORT"); port != "" {
		if port != "443" && port != "9443" {
			log.Fatal("invalid staging service port")
		}
		service.Server.Addr = ":" + port
	}
	stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = service.Server.Shutdown(ctx)
		_ = service.Client.Disconnect(ctx)
	}()
	log.Print("staging Identity TLS service started")
	if err := service.Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal("staging Identity TLS listener stopped")
	}
	<-drained
}

func healthcheck() bool {
	cfg, err := identityruntime.LoadServiceConfig(os.Getenv("IDENTITY_STAGING_CONFIG_FILE"))
	if err != nil {
		return false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.TLSCertificate)) {
		return false
	}
	port := os.Getenv("IDENTITY_INTERNAL_PORT")
	if port == "" {
		port = "9443"
	}
	if port != "443" && port != "9443" {
		return false
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "id-staging.shadowops.dpdns.org"}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", "https://127.0.0.1:"+port+"/readyz", nil)
	if err != nil {
		return false
	}
	req.Host = "id-staging.shadowops.dpdns.org"
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	return response.StatusCode == 200
}
