package production

import (
 "context"
 "errors"
 "fmt"
 "net/url"
 "os"
 "strings"
 "testing"
 "time"
)

// This gate runs ONLY against a locally bootstrapped, disposable TLS MongoDB
// replica. It exercises the actual production startup privilege check and
// transaction-backed account/session path, never external operator custody.
func TestDisposableTLSMongoProductionRoleAndFailClosedDrift(t *testing.T) {
 if os.Getenv("IDENTITY_PRODUCTION_MONGO_LIVE_CI")!="1" || os.Getenv("GITHUB_ACTIONS")!="true" {
  t.Skip("explicit ephemeral production-role TLS CI fixture not configured")
 }
 const host="127.0.0.1:27029"
 const replica="identity-prod-ci-rs"
 pw:=os.Getenv("IDENTITY_PRODUCTION_TEST_RUNTIME_PASSWORD")
 ca:=os.Getenv("IDENTITY_PRODUCTION_TEST_CA_FILE")
 if len(pw)<24 || !strings.HasPrefix(ca,"/tmp/identity-prod-mongo-ci-") {
  t.Fatal("refusing absent or non-ephemeral fixture material")
 }
 raw,err:=os.ReadFile(ca)
 if err!=nil || !strings.Contains(string(raw),"BEGIN CERTIFICATE") {t.Fatal("ephemeral CA unavailable")}
 uri:="mongodb://"+url.UserPassword("identity_prod_runtime",pw).String()+"@"+host+"/"+
  Database+"?tls=true&authSource="+Database+"&replicaSet="+replica
 parsed,err:=url.Parse(uri)
 if err!=nil || parsed.Host!=host || parsed.Path!="/"+Database ||
  parsed.Query().Get("replicaSet")!=replica || parsed.Query().Get("authSource")!=Database ||
  parsed.Query().Get("tls")!="true" {
  t.Fatal("refusing non-local Mongo test target")
 }
 cfg:=fixture(t)
 cfg.MongoURI=uri
 cfg.MongoCA=string(raw)
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
 defer cancel()
 running,err:=NewProductionService(ctx,cfg)
 drift:=os.Getenv("IDENTITY_PRODUCTION_MONGO_EXPECT_DRIFT")=="1"
 if drift {
  if running!=nil {
   _=running.Client.Disconnect(context.Background())
   t.Fatal("production runtime started after privilege broadening")
  }
  if !errors.Is(err,ErrProductionUnavailable) {
   t.Fatal("unexpected role-drift rejection result")
  }
  return
 }
 if err!=nil || running==nil {t.Fatal("scoped production Mongo principal could not start runtime",err)}
 defer running.Client.Disconnect(context.Background())
 if err:=verifyProductionMongoRole(ctx,running.Client);err!=nil {t.Fatal("live role verifier rejected exact grants")}
 if err:=verifyProductionReplica(ctx,running.Client);err!=nil {t.Fatal("writable replica refused")}
 if err:=running.ProvisionNativeAccount(ctx,"ci_prod_user","fixture password private only to isolated CI");err!=nil {
  t.Fatal("scoped native account provisioning failed",err)
 }
 handle,err:=running.accounts.Issue(ctx,"ci_prod_user","fixture password private only to isolated CI")
 if err!=nil || !strings.HasPrefix(handle,"so1_") {t.Fatal("transactional production session was not issued")}
 if err:=running.accounts.Logout(ctx,handle);err!=nil {t.Fatal("scoped production logout failed",err)}
 if _,err:=running.accounts.Validate(ctx,handle);err==nil {t.Fatal("revoked production session remained accepted")}
 t.Log(fmt.Sprintf("actual production runtime accepted exact Mongo role and revoked session on TLS replica %s",replica))
}
