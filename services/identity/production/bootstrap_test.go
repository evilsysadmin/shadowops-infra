package production

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/base64"
 "encoding/json"
 "encoding/pem"
 "math/big"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func encoded(b byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b},32)) }

func fixture(t *testing.T) Bundle {
 t.Helper()
 now:=time.Now().UTC()
 caKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil {t.Fatal(err)}
 ca:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"synthetic production CA"},IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature,NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)}
 caDER,err:=x509.CreateCertificate(rand.Reader,ca,ca,&caKey.PublicKey,caKey);if err!=nil {t.Fatal(err)}
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil {t.Fatal(err)}
 leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:Host},DNSNames:[]string{Host},ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},KeyUsage:x509.KeyUsageDigitalSignature,NotBefore:now.Add(-time.Minute),NotAfter:now.Add(time.Hour)}
 der,err:=x509.CreateCertificate(rand.Reader,leaf,ca,&key.PublicKey,caKey);if err!=nil {t.Fatal(err)}
 keyDER,err:=x509.MarshalPKCS8PrivateKey(key);if err!=nil {t.Fatal(err)}
 return Bundle{Environment:"production",MongoURI:"mongodb://prod_user:synthetic-secret@127.0.0.1:27019/"+Database+"?tls=true",MongoCA:string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:caDER})),SigningSeed:encoded(0x21),TLSCert:string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})),TLSKey:string(pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER})),Consumers:map[string]string{Audience:"soc1_"+encoded(0x42)}}
}

func TestPrivateConfigAndScopedTLS(t *testing.T){
 b:=fixture(t)
 cert,err:=b.Validate(time.Now());if err!=nil||len(cert.Certificate)!=1{t.Fatal(err)}
 data,_:=json.Marshal(b)
 path:=filepath.Join(t.TempDir(),"prod.json")
 if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
 loaded,_,err:=LoadBundle(path);if err!=nil||loaded.Environment!="production"{t.Fatal(err)}
 if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
 if _,_,err:=LoadBundle(path);err==nil{t.Fatal("world readable prod key")}
 if err:=os.Chmod(path,0600);err!=nil{t.Fatal(err)}
 link:=filepath.Join(t.TempDir(),"link.json");if err:=os.Symlink(path,link);err!=nil{t.Fatal(err)}
 if _,_,err:=LoadBundle(link);err==nil{t.Fatal("symlink prod key")}
 if _,_,err:=LoadBundle("relative.json");err==nil{t.Fatal("relative prod key")}
}

func TestRejectMalformedPrivateJSON(t *testing.T){
 b:=fixture(t);valid,_:=json.Marshal(b)
 for _,raw:=range [][]byte{append(bytes.Clone(valid),[]byte("\n{}")...),[]byte("{\"environment\":\"production\",\"unknown\":1}"),[]byte("null"),bytes.Repeat([]byte(" "),131073)}{
  file:=filepath.Join(t.TempDir(),"bad.json")
  if err:=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
  if _,_,err:=LoadBundle(file);err==nil{t.Fatal("bad config admitted")}
 }
}

func TestRefusesStagingCrossAudienceAndUnsafeMongo(t *testing.T){
 b:=fixture(t)
 cases:=map[string]func(*Bundle){
  "staging":func(x *Bundle){x.Environment="staging"},
  "prod typo":func(x *Bundle){x.Environment="prod"},
  "empty consumer":func(x *Bundle){x.Consumers=nil},
  "foreign consumer":func(x *Bundle){x.Consumers=map[string]string{"snooker":b.Consumers[Audience]}},
  "multiple consumers":func(x *Bundle){x.Consumers["football"]=b.Consumers[Audience]},
  "weak proof":func(x *Bundle){x.Consumers[Audience]="soc1_bad"},
  "reused seed":func(x *Bundle){x.Consumers[Audience]="soc1_"+x.SigningSeed},
  "short seed":func(x *Bundle){x.SigningSeed=x.SigningSeed[:42]},
  "staging db":func(x *Bundle){x.MongoURI=strings.Replace(x.MongoURI,Database,"shadowops_identity_staging",1)},
  "no TLS":func(x *Bundle){x.MongoURI=strings.Replace(x.MongoURI,"?tls=true","",1)},
  "insecure TLS":func(x *Bundle){x.MongoURI+="&tlsAllowInvalidCertificates=true"},
  "unauthenticated Mongo":func(x *Bundle){x.MongoURI="mongodb://127.0.0.1:27019/"+Database+"?tls=true"},
  "missing Mongo pass":func(x *Bundle){x.MongoURI="mongodb://prod_user@127.0.0.1:27019/"+Database+"?tls=true"},
  "CA missing":func(x *Bundle){x.MongoCA=""},
  "CA invalid":func(x *Bundle){x.MongoCA="invalid"},
  "cert missing":func(x *Bundle){x.TLSCert=""},
 }
 for name,change:=range cases{
  t.Run(name,func(t *testing.T){
   x:=b;x.Consumers=map[string]string{Audience:b.Consumers[Audience]};change(&x)
   if _,err:=x.Validate(time.Now());err==nil{t.Fatal("unsafe production config admitted")}
  })
 }
 if _,err:=b.Validate(time.Now().Add(2*time.Hour));err==nil{t.Fatal("expired TLS accepted")}
}

func TestUnreadyHTTPCannotIssueTokensOrKeys(t *testing.T){
 for _,tc:=range []struct{method,path,host string; tls bool; code int}{
  {"GET","/livez",Host,true,200},
  {"GET","/readyz",Host,true,503},
  {"GET","/api/identity/jwks",Host,true,503},
  {"GET","/login?app=bridgesquad",Host,true,503},
  {"POST","/api/identity/login",Host,true,503},
  {"POST","/api/identity/token",Host,true,503},
  {"POST","/api/identity/freshness",Host,true,503},
  {"GET","/livez","id-staging.shadowops.dpdns.org",true,403},
  {"GET","/api/identity/jwks",Host,false,403},
  {"GET","/unknown",Host,true,404},
 } {
  req:=httptest.NewRequest(tc.method,"https://"+Host+tc.path,nil)
  req.Host=tc.host
  if !tc.tls{req.TLS=nil}else{req.TLS=&tls.ConnectionState{}}
  rec:=httptest.NewRecorder();UnreadyHandler().ServeHTTP(rec,req)
  if rec.Code!=tc.code{t.Fatalf("%s %s: %d, want %d",tc.method,tc.path,rec.Code,tc.code)}
  if rec.Header().Get("Set-Cookie")!=""||rec.Header().Get("Cache-Control")!="no-store"{t.Fatal("leaked browser cookie/cache")}
  if strings.Contains(rec.Body.String(),"\"keys\"")||strings.Contains(rec.Body.String(),"eyJ"){t.Fatal("unready served token")}
 }
}

func TestServerNeedsValidatedCertificate(t *testing.T){
 if _,err:=NewUnreadyServer(tls.Certificate{});err==nil{t.Fatal("empty certificate accepted")}
 cert,err:=fixture(t).Validate(time.Now());if err!=nil{t.Fatal(err)}
 srv,err:=NewUnreadyServer(cert)
 if err!=nil||srv.Addr!=":9443"||srv.TLSConfig.MinVersion!=tls.VersionTLS12{t.Fatal("wrong TLS server",err)}
 _=srv.Close()
}
