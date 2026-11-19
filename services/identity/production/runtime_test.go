package production

import (
 "context"
 "crypto/tls"
 "errors"
 "net/http/httptest"
 "testing"
 "time"

 "go.mongodb.org/mongo-driver/v2/bson"
)

func validProductionPrivilegeStatus()productionMongoStatus{
 var state productionMongoStatus
 raw,err:=bson.Marshal(bson.M{"authInfo":bson.M{
  "authenticatedUsers":[]bson.M{{"user":"identity_prod_runtime","db":Database}},
  "authenticatedUserRoles":[]bson.M{{"role":productionMongoRole,"db":Database}},
  "authenticatedUserPrivileges":[]bson.M{
   {"resource":bson.M{"db":Database,"collection":sessionCollectionName},
    "actions":[]string{"find","insert","update","remove","createIndex","listIndexes"}},
   {"resource":bson.M{"db":Database,"collection":accountCollectionName},
    "actions":[]string{"find","insert","update","createIndex","listIndexes"}},
   {"resource":bson.M{"db":Database,"collection":productionTokenCollection},
    "actions":[]string{"find","insert","update","createIndex","listIndexes"}},
  },
 }})
 if err!=nil{panic(err)}
 if bson.Unmarshal(raw,&state)!=nil{panic("broken synthetic Mongo authorization fixture")}
 return state
}

func TestProductionRoleRequiresExactThreeCollectionsAndCollectionScopedGrants(t *testing.T){
 if err:=ValidateProductionPrivileges(validProductionPrivilegeStatus());err!=nil{
  t.Fatal("exact production application role rejected",err)
 }
 cases:=map[string]func(*productionMongoStatus){
  "no user":func(s *productionMongoStatus){s.Auth.Users=nil},
  "two authenticated users":func(s *productionMongoStatus){s.Auth.Users=append(s.Auth.Users,bson.M{"user":"another"})},
  "no roles":func(s *productionMongoStatus){s.Auth.Roles=nil},
  "wrong role":func(s *productionMongoStatus){s.Auth.Roles[0].Role="readWrite"},
  "staging role":func(s *productionMongoStatus){s.Auth.Roles[0].DB="shadowops_identity_staging"},
  "extra role":func(s *productionMongoStatus){s.Auth.Roles=append(s.Auth.Roles,s.Auth.Roles[0])},
  "no index on sessions":func(s *productionMongoStatus){s.Auth.Privileges[0].Actions=[]string{"find","insert","update","remove","listIndexes"}},
  "no revocation":func(s *productionMongoStatus){s.Auth.Privileges[0].Actions=[]string{"find","insert","update","createIndex","listIndexes"}},
  "no account collection":func(s *productionMongoStatus){s.Auth.Privileges=s.Auth.Privileges[1:]},
  "no token collection":func(s *productionMongoStatus){s.Auth.Privileges=s.Auth.Privileges[:2]},
  "admin wildcard":func(s *productionMongoStatus){s.Auth.Privileges[0].Resource.Collection=""},
  "cluster wildcard":func(s *productionMongoStatus){s.Auth.Privileges[0].Resource.Cluster=true},
  "any resource":func(s *productionMongoStatus){s.Auth.Privileges[0].Resource.Any=true},
  "other DB":func(s *productionMongoStatus){s.Auth.Privileges[0].Resource.DB="shadowops_identity_staging"},
  "drop collection":func(s *productionMongoStatus){s.Auth.Privileges[0].Actions=append(s.Auth.Privileges[0].Actions,"dropCollection")},
  "manage role":func(s *productionMongoStatus){s.Auth.Privileges[0].Actions=append(s.Auth.Privileges[0].Actions,"grantRole")},
  "readWrite database":func(s *productionMongoStatus){s.Auth.Privileges[0].Resource.Collection="";s.Auth.Privileges[0].Actions=[]string{"find","insert"}},
 }
 for name,fn:=range cases{
  t.Run(name,func(t *testing.T){
   state:=validProductionPrivilegeStatus()
   fn(&state)
   if err:=ValidateProductionPrivileges(state);!errors.Is(err,ErrProductionUnavailable){
    t.Fatal("untrusted Mongo authorization accepted",err)
   }
  })
 }
}

func TestProductionRuntimeRefusesInvalidBundleBeforeAnyNetwork(t *testing.T){
 cfg:=fixture(t)
 cfg.Environment="staging"
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 defer cancel()
 if _,err:=NewProductionService(ctx,cfg);!errors.Is(err,ErrProductionUnavailable){
  t.Fatal("staging config admitted to production",err)
 }
 cfg=fixture(t)
 stop,finish:=context.WithCancel(context.Background())
 finish()
 if _,err:=NewProductionService(stop,cfg);!errors.Is(err,ErrProductionUnavailable){
  t.Fatal("cancelled production start reached Mongo",err)
 }
 if _,err:=newProductionHTTPServer(tls.Certificate{},nil,nil);!errors.Is(err,ErrProductionUnavailable){
  t.Fatal("empty production listener materials accepted",err)
 }
}

func TestLiveProductionServerRequiresExactTLSHostAndMongoReplica(t *testing.T){
 _,database:=productionReplica(t)
 cert,err:=fixture(t).Validate(time.Now())
 if err!=nil{t.Fatal(err)}
 h,_ ,_,_:=setupBrowser()
 server,err:=newProductionHTTPServer(cert,database.Client(),h)
 if err!=nil{t.Fatal(err)}
 if server.Addr!=":9443"||server.TLSConfig.MinVersion!=tls.VersionTLS12{
  t.Fatal("production TLS port/config invalid")
 }
 for _,tc:=range []struct{route,method,host string; tls bool;want int}{
  {"/livez","GET",Host,true,200},
  {"/readyz","GET",Host,true,200},
  {"/readyz","POST",Host,true,405},
  {"/readyz?host=staging","GET",Host,true,405},
  {"/livez","GET",Host,false,403},
  {"/readyz","GET","id-staging.shadowops.dpdns.org",true,403},
  {"/api/identity/register","POST",Host,true,503},
 }{
  req:=httptest.NewRequest(tc.method,"https://"+Host+tc.route,nil)
  req.Host=tc.host
  if tc.tls {req.TLS=&tls.ConnectionState{}}else{req.TLS=nil}
  rec:=httptest.NewRecorder()
  server.Handler.ServeHTTP(rec,req)
  if rec.Code!=tc.want || rec.Header().Get("Cache-Control")!="no-store"{
   t.Fatalf("%s %s TLS=%v got=%d want=%d",tc.method,tc.route,tc.tls,rec.Code,tc.want)
  }
 }
}

func TestAccountProvisioningCannotUseAnUninitializedProductionRuntime(t *testing.T){
 var absent *RunningProduction
 ctx:=context.Background()
 if err:=absent.ProvisionNativeAccount(ctx,"operator","a-strong-sample-passphrase");!errors.Is(err,ErrProductionUnavailable){t.Fatal("nil runtime authorized account provisioning")}
 if err:=(&RunningProduction{}).ProvisionNativeAccount(ctx,"operator","a-strong-sample-passphrase");!errors.Is(err,ErrProductionUnavailable){t.Fatal("uninitialized runtime authorized account provisioning")}
}
