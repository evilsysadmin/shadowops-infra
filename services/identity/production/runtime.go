package production

// Production runtime composition is deliberately separate from every staging
// package. An opt-in startup must prove private TLS bundle, a scoped Mongo
// identity and a writable replica set BEFORE creating indexes or HTTP routes.
import (
 "context"
 "crypto/ed25519"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "errors"
 "io"
 "net/http"
 "time"

 "go.mongodb.org/mongo-driver/v2/bson"
 "go.mongodb.org/mongo-driver/v2/mongo"
 "go.mongodb.org/mongo-driver/v2/mongo/options"
 "go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

const productionMongoRole = "shadowops_identity_production_runtime"

var ErrProductionUnavailable = errors.New("production Identity runtime not ready")

type productionPrivilege struct {
 Resource struct {
  DB string `bson:"db"`
  Collection string `bson:"collection"`
  Any bool `bson:"anyResource"`
  Cluster bool `bson:"cluster"`
 } `bson:"resource"`
 Actions []string `bson:"actions"`
}
type productionMongoStatus struct {
 Auth struct {
  Users []bson.M `bson:"authenticatedUsers"`
  Roles []struct{
   Role string `bson:"role"`
   DB string `bson:"db"`
  } `bson:"authenticatedUserRoles"`
  Privileges []productionPrivilege `bson:"authenticatedUserPrivileges"`
 } `bson:"authInfo"`
}

func requiredProductionPrivilegeActions() map[string]map[string]bool {
 required:=map[string]map[string]bool{}
 for _,name:=range []string{sessionCollectionName,accountCollectionName,productionTokenCollection}{
  required[name]=map[string]bool{
   "find":false,"insert":false,"update":false,
   "createIndex":false,"listIndexes":false,
  }
 }
 required[sessionCollectionName]["remove"]=false
 return required
}

// ValidateProductionPrivileges never permits a database wildcard, any admin
// grant, roles for other databases or unknown Mongo actions. Collection
// creation and account/role administration must be done offline by an operator.
func ValidateProductionPrivileges(status productionMongoStatus)error{
 auth:=status.Auth
 if len(auth.Users)!=1 || len(auth.Roles)!=1 ||
  auth.Roles[0].Role!=productionMongoRole || auth.Roles[0].DB!=Database ||
  len(auth.Privileges)==0 {return ErrProductionUnavailable}
 required:=requiredProductionPrivilegeActions()
 for _,grant:=range auth.Privileges{
  if grant.Resource.Any || grant.Resource.Cluster ||
   grant.Resource.DB!=Database || grant.Resource.Collection=="" ||
   len(grant.Actions)==0 {return ErrProductionUnavailable}
  actions,known:=required[grant.Resource.Collection]
  if !known{return ErrProductionUnavailable}
  for _,action:=range grant.Actions{
   if _,ok:=actions[action];!ok{return ErrProductionUnavailable}
   actions[action]=true
  }
 }
 for _,actions:=range required{
  for _,seen:=range actions{if !seen{return ErrProductionUnavailable}}
 }
 return nil
}

func verifyProductionMongoRole(ctx context.Context,client *mongo.Client)error{
 if ctx==nil || ctx.Err()!=nil || client==nil{return ErrProductionUnavailable}
 var status productionMongoStatus
 if err:=client.Database("admin").RunCommand(ctx,bson.D{
  {Key:"connectionStatus",Value:1},
  {Key:"showPrivileges",Value:true},
 }).Decode(&status);err!=nil{return ErrProductionUnavailable}
 return ValidateProductionPrivileges(status)
}

func verifyProductionReplica(ctx context.Context,client *mongo.Client)error{
 if ctx==nil || ctx.Err()!=nil || client==nil{return ErrProductionUnavailable}
 if err:=client.Ping(ctx,readpref.Primary());err!=nil{return ErrProductionUnavailable}
 var hello struct{
  SetName string `bson:"setName"`
  IsWritablePrimary bool `bson:"isWritablePrimary"`
 }
 if err:=client.Database("admin").RunCommand(ctx,bson.D{{Key:"hello",Value:1}}).Decode(&hello);err!=nil||
  hello.SetName=="" || !hello.IsWritablePrimary {return ErrProductionUnavailable}
 return nil
}

type RunningProduction struct {
 Server *http.Server
 Client *mongo.Client
}

// NewProductionService is not reachable from the staging runtime. A production
// process must explicitly invoke it after reading a restrictive operator bundle.
// Authentication and issuance are enabled ONLY after all checks complete.
func NewProductionService(ctx context.Context,cfg Bundle)(*RunningProduction,error){
 if ctx==nil || ctx.Err()!=nil{return nil,ErrProductionUnavailable}
 cert,err:=cfg.Validate(time.Now().UTC())
 if err!=nil{return nil,ErrProductionUnavailable}
 seed,err:=base64.RawURLEncoding.DecodeString(cfg.SigningSeed)
 if err!=nil || len(seed)!=ed25519.SeedSize{return nil,ErrProductionUnavailable}
 defer clear(seed)
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM([]byte(cfg.MongoCA)){return nil,ErrProductionUnavailable}
 mongoTLS:=&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots}
 client,err:=mongo.Connect(options.Client().ApplyURI(cfg.MongoURI).
  SetTLSConfig(mongoTLS).
  SetConnectTimeout(3*time.Second).
  SetServerSelectionTimeout(3*time.Second))
 if err!=nil{return nil,ErrProductionUnavailable}
 opened:=false
 defer func(){if !opened{
  stop,cancel:=context.WithTimeout(context.Background(),3*time.Second)
  defer cancel()
  _=client.Disconnect(stop)
 }}()
 if verifyProductionMongoRole(ctx,client)!=nil || verifyProductionReplica(ctx,client)!=nil{
  return nil,ErrProductionUnavailable
 }
 accounts,err:=NewAccountAuthority(ctx,client)
 if err!=nil{return nil,ErrProductionUnavailable}
 tokens,err:=NewProductionAppTokens(ctx,accounts,seed)
 if err!=nil{return nil,ErrProductionUnavailable}
 proof:=cfg.Consumers[Audience]
 handler,err:=NewProductionBrowserHandler(accounts,tokens,proof)
 if err!=nil{return nil,ErrProductionUnavailable}
 server,err:=newProductionHTTPServer(cert,client,handler)
 if err!=nil{return nil,ErrProductionUnavailable}
 opened=true
 return &RunningProduction{Server:server,Client:client},nil
}

// newProductionHTTPServer can be exercised using a disposable test Mongo
// replica, but it MUST never be used with staging credentials in a live process.
func newProductionHTTPServer(cert tls.Certificate,client *mongo.Client,handler http.Handler)(*http.Server,error){
 if len(cert.Certificate)==0 || cert.PrivateKey==nil || client==nil || handler==nil{
  return nil,ErrProductionUnavailable
 }
 routed:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  productionHeaders(w)
  if r==nil || r.TLS==nil || r.Host!=Host{
   productionFailure(w,http.StatusForbidden);return
  }
  if r.URL.RawQuery=="" && r.Method==http.MethodGet && r.URL.Path=="/livez"{
   w.WriteHeader(http.StatusOK)
   _,_=io.WriteString(w,"production identity service alive\n")
   return
  }
  if r.URL.Path=="/readyz"{
   if r.Method!=http.MethodGet || r.URL.RawQuery!=""{
    productionFailure(w,http.StatusMethodNotAllowed);return
   }
   ctx,cancel:=context.WithTimeout(r.Context(),2*time.Second)
   defer cancel()
   if verifyProductionReplica(ctx,client)!=nil{
    productionFailure(w,http.StatusServiceUnavailable);return
   }
   w.WriteHeader(http.StatusOK)
   _,_=io.WriteString(w,"production identity ready\n")
   return
  }
  handler.ServeHTTP(w,r)
 })
 return &http.Server{
  Addr:":9443",Handler:routed,
  TLSConfig:&tls.Config{MinVersion:tls.VersionTLS12,Certificates:[]tls.Certificate{cert}},
  ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,
  WriteTimeout:10*time.Second,IdleTimeout:30*time.Second,
  MaxHeaderBytes:8<<10,
 },nil
}
