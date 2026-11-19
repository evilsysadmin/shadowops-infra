// service-production has NO implicit startup: run explicitly in preflight,
// serve-unready, or serve-ready mode after provisioning an isolated production
// TLS key, Mongo replica, least-privilege role, signing key and consumer proof.
// No GitHub workflow deploys this command to production.
package main

import (
 "bytes"
 "context"
 "errors"
 "io"
 "log"
 "unicode/utf8"
 "net/http"
 "os"
 "os/signal"
 "syscall"
 "time"

 "github.com/evilsysadmin/shadowops-infra/services/identity/production"
)

// readNativePassword accepts a single secret from an anonymous pipe.
// It never accepts flags, environment variables, interactive echo or files.
func readNativePassword(source io.Reader)(string,error){
 raw,err:=io.ReadAll(io.LimitReader(source,4098))
 if err!=nil || len(raw)==0 || len(raw)>4097 {clear(raw);return "",errors.New("invalid password input")}
 if raw[len(raw)-1]=='\n'{raw=raw[:len(raw)-1]}
 if len(raw)>4096 || !utf8.Valid(raw) || utf8.RuneCount(raw)<15 ||
  bytes.IndexAny(raw,"\x00\r\n")>=0 {clear(raw);return "",errors.New("invalid password input")}
 secret:=string(raw)
 clear(raw)
 return secret,nil
}

func provisionNativeAccount(cfg production.Bundle,alias string)error{
 stat,err:=os.Stdin.Stat()
 if err!=nil || stat.Mode()&os.ModeNamedPipe==0{return errors.New("password must arrive over an anonymous stdin pipe")}
 password,err:=readNativePassword(os.Stdin)
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),35*time.Second)
 defer cancel()
 running,err:=production.NewProductionService(ctx,cfg)
 if err!=nil{return err}
 defer func(){
  stop,done:=context.WithTimeout(context.Background(),5*time.Second)
  defer done()
  _=running.Client.Disconnect(stop)
 }()
 return running.ProvisionNativeAccount(ctx,alias,password)
}

func main() {
 mode,alias:="",""
 if len(os.Args)==2 && (os.Args[1]=="preflight" || os.Args[1]=="serve-unready" || os.Args[1]=="serve-ready"){
  mode=os.Args[1]
 }else if len(os.Args)==3 && os.Args[1]=="provision-native-account"{
  mode,alias=os.Args[1],os.Args[2]
 }else{
  log.Fatal("expected preflight, serve-unready, serve-ready or provision-native-account ALIAS")
 }
 cfg,cert,err:=production.LoadBundle(os.Getenv("IDENTITY_PRODUCTION_CONFIG_FILE"))
 if err!=nil{
  log.Fatal("invalid private production Identity configuration")
 }
 if mode=="preflight"{
  log.Print("private production TLS bundle validated OFFLINE; no Mongo connection, login or JWT activated")
  return
 }
 if mode=="provision-native-account"{
  if err:=provisionNativeAccount(cfg,alias);err!=nil{log.Fatal("production native account provisioning denied")}
  log.Print("production native account provisioned; no HTTP listener started")
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
