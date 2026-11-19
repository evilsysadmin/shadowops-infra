// service-production has NO implicit startup: run explicitly in preflight,
// serve-unready, or serve-ready mode after provisioning an isolated production
// TLS key, Mongo replica, least-privilege role, signing key and consumer proof.
// No GitHub workflow deploys this command to production.
package main

import (
 "context"
 "log"
 "net/http"
 "os"
 "os/signal"
 "syscall"
 "time"

 "github.com/evilsysadmin/shadowops-infra/services/identity/production"
)

func main() {
 if len(os.Args)!=2 || (os.Args[1]!="preflight" && os.Args[1]!="serve-unready" && os.Args[1]!="serve-ready"){
  log.Fatal("expected explicit preflight, serve-unready or serve-ready mode")
 }
 cfg,cert,err:=production.LoadBundle(os.Getenv("IDENTITY_PRODUCTION_CONFIG_FILE"))
 if err!=nil{
  log.Fatal("invalid private production Identity configuration")
 }
 mode:=os.Args[1]
 if mode=="preflight"{
  log.Print("private production TLS bundle validated OFFLINE; no Mongo connection, login or JWT activated")
  return
 }
 if mode=="serve-unready"{
  cfg.MongoURI="";cfg.MongoCA="";cfg.SigningSeed="";cfg.TLSKey=""
  for name:=range cfg.Consumers{delete(cfg.Consumers,name)}
  server,err:=production.NewUnreadyServer(cert)
  if err!=nil{log.Fatal("production unready TLS bootstrap denied")}
  log.Print("production TLS bootstrap UNREADY: no sessions, login or JWKS")
  if err:=server.ListenAndServeTLS("","");err!=nil && err!=http.ErrServerClosed{
   log.Fatal("production unready TLS bootstrap stopped")
  }
  return
 }
 // serve-ready is an explicit operator decision. Fail closed on any Mongo
 // authentication, replica, role, index, signer or service proof failure.
 start,cancel:=context.WithTimeout(context.Background(),25*time.Second)
 running,err:=production.NewProductionService(start,cfg)
 cancel()
 cfg.MongoURI="";cfg.MongoCA="";cfg.SigningSeed="";cfg.TLSKey=""
 for name:=range cfg.Consumers{delete(cfg.Consumers,name)}
 if err!=nil{log.Fatal("production Identity runtime admission denied")}
 port:=os.Getenv("IDENTITY_INTERNAL_PORT")
 if port!=""{
  if port!="443" && port!="9443"{log.Fatal("invalid production Identity TLS port")}
  running.Server.Addr=":"+port
 }
 stop,done:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer done()
 drained:=make(chan struct{})
 go func(){
  defer close(drained)
  <-stop.Done()
  ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
  defer cancel()
  _=running.Server.Shutdown(ctx)
  _=running.Client.Disconnect(ctx)
 }()
 log.Print("production Identity TLS service started with verified isolated Mongo role")
 if err:=running.Server.ListenAndServeTLS("","");err!=nil && err!=http.ErrServerClosed{
  // Never include provider connection details or private credentials in logs.
  log.Print("production Identity TLS listener stopped")
  stopNow,c:=context.WithTimeout(context.Background(),5*time.Second)
  _=running.Client.Disconnect(stopNow)
  c()
  os.Exit(1)
 }
 // Termination without a signal is considered abnormal, not a successful
 // production runtime completion.
 <-drained
}
