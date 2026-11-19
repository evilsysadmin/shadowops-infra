package production

import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/tls"
 "encoding/base64"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)

const fakeSubject = "11111111-1111-4111-8111-111111111111"

type fakeFreshness struct {
 called int
 evidence FreshnessEvidence
 failure error
 keys []byte
}
func (f *fakeFreshness) CheckBound(_ context.Context,subject string,version int64,jti string)(FreshnessEvidence,error){
 f.called++
 if f.failure!=nil{return FreshnessEvidence{},f.failure}
 return f.evidence,nil
}
func (f *fakeFreshness) JWKS()([]byte,error){
 if len(f.keys)==0{return nil,ErrAccountStore}
 return f.keys,nil
}
func syntheticProof()string{
 return "soc1_"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42},32))
}
func syntheticJTI()string{
 return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31},16))
}
func testFreshnessHandler()(*ProductionFreshnessHandler,*fakeFreshness){
 proof:=syntheticProof()
 hash,_:=credentialHash(proof)
 evidence:=FreshnessEvidence{Issuer:productionIssuer,Audience:Audience,Subject:fakeSubject,
  SessionVersion:4,TokenJTI:syntheticJTI(),CheckedAt:time.Now().Unix(),
  AccountActive:true,SessionActive:true,TokenActive:true}
 fake:=&fakeFreshness{evidence:evidence,keys:[]byte(`{"keys":[]}`)}
 return &ProductionFreshnessHandler{authority:fake,secretHash:hash},fake
}
func validFreshnessRequest() *http.Request {
 raw,_:=json.Marshal(map[string]any{
  "subject":fakeSubject,"session_version":int64(4),"token_jti":syntheticJTI(),
 })
 req:=httptest.NewRequest("POST","https://"+Host+ProductionFreshnessPath,bytes.NewReader(raw))
 req.Host=Host
 req.TLS=&tls.ConnectionState{}
 req.Header.Set("Authorization","Bearer "+syntheticProof())
 req.Header.Set("Content-Type","application/json")
 return req
}
func invoke(h http.Handler,req *http.Request) *httptest.ResponseRecorder{
 rec:=httptest.NewRecorder()
 h.ServeHTTP(rec,req)
 return rec
}

func TestProductionFreshnessStrictServiceAuthentication(t *testing.T){
 for name,change:=range map[string]func(*http.Request){
  "missing bearer":func(r *http.Request){r.Header.Del("Authorization")},
  "wrong bearer":func(r *http.Request){r.Header.Set("Authorization","Bearer "+"soc1_"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99},32)))},
  "malformed bearer":func(r *http.Request){r.Header.Set("Authorization","Basic test")},
  "duplicate bearer":func(r *http.Request){r.Header.Add("Authorization","Bearer "+syntheticProof())},
  "browser cookie":func(r *http.Request){r.Header.Add("Cookie","__Host-shadowops_sso_prod=abc")},
  "browser origin":func(r *http.Request){r.Header.Add("Origin",Origin)},
  "staging origin":func(r *http.Request){r.Header.Add("Origin","https://id-staging.shadowops.dpdns.org")},
  "referer":func(r *http.Request){r.Header.Add("Referer",Origin)},
  "fetch metadata":func(r *http.Request){r.Header.Add("Sec-Fetch-Site","same-site")},
  "plain http":func(r *http.Request){r.TLS=nil},
  "wrong host":func(r *http.Request){r.Host="id-staging.shadowops.dpdns.org"},
  "spoof forwarded host":func(r *http.Request){r.Host="evil.test";r.Header.Set("X-Forwarded-Host",Host)},
  "missing remote peer":func(r *http.Request){r.RemoteAddr=""},
 }{
  t.Run(name,func(t *testing.T){
   h,fake:=testFreshnessHandler()
   req:=validFreshnessRequest()
   change(req)
   rec:=invoke(h,req)
   if rec.Code!=401 && rec.Code!=403 {
    t.Fatalf("unauthorized request accepted with %d",rec.Code)
   }
   if fake.called!=0{t.Fatal("unauthorized request touched token ledger")}
   if rec.Header().Get("Set-Cookie")!="" || rec.Header().Get("Cache-Control")!="no-store"{
    t.Fatal("authentication response leaked cookie or cacheability")
   }
  })
 }
}
func TestProductionFreshnessStrictJSONAndMethodContract(t *testing.T){
 for name,change:=range map[string]func(*http.Request){
  "GET":func(r *http.Request){r.Method="GET"},
  "query":func(r *http.Request){r.URL.RawQuery="audience=football"},
  "non JSON":func(r *http.Request){r.Header.Set("Content-Type","text/plain")},
  "duplicate media":func(r *http.Request){r.Header.Add("Content-Type","application/json")},
  "encoded":func(r *http.Request){r.Header.Set("Content-Encoding","gzip")},
  "too large":func(r *http.Request){r.Body=http.NoBody;r.Body=ioNopCloser(strings.NewReader(strings.Repeat("a",4097)))},
  "null":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader("null"))},
  "unknown audience":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader(`{"subject":"11111111-1111-4111-8111-111111111111","session_version":4,"token_jti":"MTExMTExMTExMTExMTExMQ","audience":"football"}`))},
  "trailing JSON":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader("{} {}"))},
  "legacy subject":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader(`{"subject":"admin","session_version":4,"token_jti":"MTExMTExMTExMTExMTExMQ"}`))},
  "no session version":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader("{}"))},
  "invalid JTI":func(r *http.Request){r.Body=ioNopCloser(strings.NewReader(`{"subject":"11111111-1111-4111-8111-111111111111","session_version":4,"token_jti":"abcdefghijklmnopqrstu!"}`))},
 } {
  t.Run(name,func(t *testing.T){
   h,fake:=testFreshnessHandler()
   req:=validFreshnessRequest()
   change(req)
   rec:=invoke(h,req)
   if rec.Code==200 || fake.called!=0{
    t.Fatalf("unsafe body/method authorized %d, called=%d",rec.Code,fake.called)
   }
  })
 }
}
type readerCloser struct{*strings.Reader}
func (*readerCloser) Close()error{return nil}
func ioNopCloser(s *strings.Reader) *readerCloser{return &readerCloser{s}}

func TestProductionFreshnessExplicitEvidenceAndErrorMapping(t *testing.T){
 h,fake:=testFreshnessHandler()
 rec:=invoke(h,validFreshnessRequest())
 if rec.Code!=200 || fake.called!=1{t.Fatalf("expected 200, got %d",rec.Code)}
 var proof FreshnessEvidence
 if json.Unmarshal(rec.Body.Bytes(),&proof)!=nil || proof.Audience!=Audience || !proof.TokenActive{
  t.Fatal("bad freshness evidence")
 }
 for _,failure:=range []struct{err error;status int}{
  {ErrAccountDenied,401},{ErrAccountStore,503},{errors.New("backend interrupted"),503},
 }{
  h,f:=testFreshnessHandler()
  f.failure=failure.err
  rec:=invoke(h,validFreshnessRequest())
  if rec.Code!=failure.status || strings.Contains(rec.Body.String(),failure.err.Error()){
   t.Fatal("invalid upstream error mapping")
  }
 }
 for _,change:=range []func(*FreshnessEvidence){
  func(e *FreshnessEvidence){e.Audience="football"},
  func(e *FreshnessEvidence){e.Subject="22222222-2222-4222-8222-222222222222"},
  func(e *FreshnessEvidence){e.TokenActive=false},
  func(e *FreshnessEvidence){e.SessionVersion=5},
  func(e *FreshnessEvidence){e.CheckedAt=0},
 }{
  h,f:=testFreshnessHandler()
  change(&f.evidence)
  if rec:=invoke(h,validFreshnessRequest());rec.Code!=503{
   t.Fatal("untrusted freshness evidence became authorization")
  }
 }
}
func TestProductionFreshnessJWKSAndReadinessRemainsClosed(t *testing.T){
 h,_:=testFreshnessHandler()
 jwks:=httptest.NewRequest("GET","https://"+Host+"/api/identity/jwks",nil)
 rec:=invoke(h,jwks)
 if rec.Code!=200 || rec.Header().Get("Content-Type")!="application/json"{t.Fatal("public JWKS not available")}
 for _,path:=range []string{"/readyz","/login?app=bridgesquad","/api/identity/token","/api/identity/login"}{
  rec:=invoke(h,httptest.NewRequest("GET","https://"+Host+path,nil))
  if rec.Code!=503{t.Fatalf("unexpected %s opening: %d",path,rec.Code)}
 }
 jwks.Header.Set("Cookie","bad=1")
 if rec:=invoke(h,jwks);rec.Code!=403{t.Fatal("public JWKS accepted browser credentials")}
}
func TestProductionFreshnessConstructorAndSecretAreIndependent(t *testing.T){
 if _,err:=NewProductionFreshnessHandler(nil,syntheticProof());!errors.Is(err,ErrAccountDenied){
  t.Fatal("nil authority accepted")
 }
 for _,bad:=range []string{"","soc1_bad","not-a-service-proof","soc1_"+strings.Repeat("A",44)} {
  if _,ok:=credentialHash(bad);ok{t.Fatal("invalid secret accepted")}
 }
 hash,ok:=credentialHash(syntheticProof())
 if !ok || hash==([32]byte{}){t.Fatal("valid independent proof rejected")}
 if hash==hashString("shadowops-consumer-v1:staging:"+syntheticProof()){
  t.Fatal("production proof not domain-separated")
 }
}
func hashString(value string)[32]byte{return sha256.Sum256([]byte(value))}
