// service-production is an explicit, unready TLS bootstrap only.
// It does not issue real sessions, tokens, JWKS or user credentials.
// Never deploy this as a functional production SSO provider.
package main

import (
 "log"
 "net/http"
 "os"

 "github.com/evilsysadmin/shadowops-infra/services/identity/production"
)

func main() {
 if len(os.Args)!=2 || (os.Args[1]!="preflight" && os.Args[1]!="serve-unready"){
  log.Fatal("expected explicit preflight or serve-unready; production login disabled")
 }
 path:=os.Getenv("IDENTITY_PRODUCTION_CONFIG_FILE")
 cfg,cert,err:=production.LoadBundle(path)
 if err!=nil {
  log.Fatal("invalid private production Identity configuration")
 }
 // Best effort remove credential copies not needed by this read-only bootstrap.
 cfg.MongoURI="";cfg.MongoCA="";cfg.SigningSeed="";cfg.TLSKey=""
 for name:=range cfg.Consumers {delete(cfg.Consumers,name)}
 if os.Args[1]=="preflight" {
  log.Print("production TLS/private-bundle admission passed; login, tokens and JWKS DISABLED")
  return
 }
 server,err:=production.NewUnreadyServer(cert)
 if err!=nil{log.Fatal("production TLS bootstrap denied")}
 log.Print("production TLS bootstrap UNREADY: no sessions, login or JWKS")
 if err:=server.ListenAndServeTLS("","");err!=nil && err!=http.ErrServerClosed {
  log.Fatal("production unready TLS bootstrap stopped")
 }
}
