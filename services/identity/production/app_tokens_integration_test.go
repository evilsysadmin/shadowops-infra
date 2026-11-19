package production

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/evilsysadmin/shadowops-infra/services/identity/core"
 "go.mongodb.org/mongo-driver/v2/bson"
)

func productionTokenFixture(t *testing.T)(*AccountAuthority,*ProductionAppTokens,string,string){
 t.Helper()
 client,db:=productionReplica(t)
 ctx:=context.Background()
 if err:=db.Collection(productionTokenCollection).Drop(ctx);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = db.Collection(productionTokenCollection).Drop(context.Background())})
 accounts,err:=NewAccountAuthority(ctx,client)
 if err!=nil{t.Fatal(err)}
 subject,err:=accounts.Register(ctx,"matthias",accountTestPass)
 if err!=nil{t.Fatal(err)}
 handle,err:=accounts.Issue(ctx,"matthias",accountTestPass)
 if err!=nil{t.Fatal(err)}
 signer,err:=NewProductionAppTokens(ctx,accounts,bytes.Repeat([]byte{0x55},32))
 if err!=nil{t.Fatal(err)}
 return accounts,signer,subject,handle
}

func TestProductionBridgeSquadJWTSessionAndLiveFreshness(t *testing.T) {
 accounts,signer,subject,handle:=productionTokenFixture(t)
 ctx:=context.Background()
 jwt,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 parts:=strings.Split(jwt,".")
 if len(parts)!=3{t.Fatal("not JWT")}
 now:=time.Now().UTC()
 claims,err:=signer.VerifySignature(jwt,now)
 if err!=nil{t.Fatal(err)}
 if claims.Iss!=productionIssuer || claims.Aud!=Audience || claims.Sub!=subject ||
  claims.Sv!=1 || claims.Exp-claims.Iat>120 || claims.Exp<=now.Unix() ||
  claims.Jti==""{t.Fatal("wrong production claims")}
 keys,err:=signer.JWKS()
 if err!=nil{t.Fatal(err)}
 var jwks core.KeySet
 if err:=json.Unmarshal(keys,&jwks);err!=nil||len(jwks.Keys)!=1{t.Fatal("invalid JWKS")}
 if jwks.Keys[0].Alg!="EdDSA"||jwks.Keys[0].Kty!="OKP"||jwks.Keys[0].Crv!="Ed25519"||
  jwks.Keys[0].Kid!=signer.kid{t.Fatal("unexpected signing key public material")}
 pub,err:=base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
 if err!=nil || !ed25519.Verify(ed25519.PublicKey(pub),[]byte(parts[0]+"."+parts[1]),
  mustDecodeJWT(t,parts[2])){t.Fatal("JWT cannot be verified with public JWKS")}
 if bytes.Contains(keys,bytes.Repeat([]byte{0x55},32)){t.Fatal("private seed published")}
 evidence,err:=signer.Check(ctx,jwt)
 if err!=nil{t.Fatal(err)}
 if evidence.Subject!=subject || evidence.Issuer!=productionIssuer ||
  evidence.Audience!=Audience || evidence.SessionVersion!=1 ||
  evidence.TokenJTI!=claims.Jti || !evidence.AccountActive ||
  !evidence.SessionActive || !evidence.TokenActive {t.Fatal("incorrect live freshness")}
 docs,err:=signer.tokens.CountDocuments(ctx,bson.D{})
 if err!=nil || docs!=1{t.Fatal("one JTI binding required")}
 var stored bson.M
 if err:=signer.tokens.FindOne(ctx,bson.D{{Key:"_id",Value:tokenID(claims.Jti)}}).Decode(&stored);err!=nil{t.Fatal(err)}
 if stored["_id"]==claims.Jti || stored["session_digest"]==handle || stored["audience"]!=Audience {
  t.Fatal("raw token or handle persisted")
 }
 if err:=accounts.SuspendAndRevoke(ctx,subject);err!=nil{t.Fatal(err)}
 if _,err:=signer.Check(ctx,jwt);!errors.Is(err,ErrAccountDenied){
  t.Fatalf("suspended token passed freshness: %v",err)
 }
 if _,err:=signer.CheckBound(ctx,subject,claims.Sv,claims.Jti);!errors.Is(err,ErrAccountDenied){
  t.Fatalf("raw JTI passed after suspension: %v",err)
 }
 if _,err:=signer.VerifySignature(jwt,time.Now().UTC());err!=nil {
  t.Fatal("JWT signing validity should be independent of revocation")
 }
}

func mustDecodeJWT(t *testing.T,s string)[]byte{
 t.Helper()
 data,err:=base64.RawURLEncoding.DecodeString(s)
 if err!=nil{t.Fatal(err)}
 return data
}

func TestProductionJWTCannotAcceptStagingIssuerAudienceOrTampering(t *testing.T){
 _,signer,subject,handle:=productionTokenFixture(t)
 jwt,err:=signer.Issue(context.Background(),handle)
 if err!=nil{t.Fatal(err)}
 claims,err:=signer.VerifySignature(jwt,time.Now())
 if err!=nil{t.Fatal(err)}
 parts:=strings.Split(jwt,".")
 sign:=func(header signedHeader,claim AppClaims)string{
  h,_:=json.Marshal(header)
  c,_:=json.Marshal(claim)
  message:=base64.RawURLEncoding.EncodeToString(h)+"."+base64.RawURLEncoding.EncodeToString(c)
  return message+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer.private,[]byte(message)))
 }
 header:=signedHeader{Alg:"EdDSA",Typ:"JWT",Kid:signer.kid}
 for name,change:=range map[string]func(*AppClaims){
  "staging issuer":func(c *AppClaims){c.Iss="https://id-staging.shadowops.dpdns.org"},
  "wrong audience":func(c *AppClaims){c.Aud="football"},
  "no version":func(c *AppClaims){c.Sv=0},
  "expired":func(c *AppClaims){c.Exp=time.Now().Add(-time.Second).Unix()},
  "too long":func(c *AppClaims){c.Exp=c.Iat+121},
  "future":func(c *AppClaims){c.Iat=time.Now().Add(time.Minute).Unix()},
  "wrong JTI":func(c *AppClaims){c.Jti="bad"},
 } {
  t.Run(name,func(t *testing.T){
   c:=claims
   change(&c)
   signed:=sign(header,c)
   if _,err:=signer.VerifySignature(signed,time.Now());!errors.Is(err,ErrAccountDenied){
    t.Fatal("invalid signed token accepted",err)
   }
  })
 }
 for _,h:=range []signedHeader{
  {Alg:"none",Typ:"JWT",Kid:signer.kid},
  {Alg:"HS256",Typ:"JWT",Kid:signer.kid},
  {Alg:"EdDSA",Typ:"JWT",Kid:"foreign-key"},
  {Alg:"EdDSA",Typ:"bearer",Kid:signer.kid},
 } {
  if _,err:=signer.VerifySignature(sign(h,claims),time.Now());!errors.Is(err,ErrAccountDenied){
   t.Fatal("invalid JWT header accepted")
  }
 }
 poisoned:=strings.Join([]string{parts[0],parts[1],base64.RawURLEncoding.EncodeToString(make([]byte,64))},".")
 if _,err:=signer.VerifySignature(poisoned,time.Now());!errors.Is(err,ErrAccountDenied){
  t.Fatal("signature forgery accepted")
 }
 foreignSubject:=claims
 foreignSubject.Sub="22222222-2222-4222-8222-222222222222"
 crossUser:=sign(header,foreignSubject)
 if _,err:=signer.VerifySignature(crossUser,time.Now());err!=nil{
  t.Fatal("cryptographically valid foreign-subject JWT must pass signature-only verification",err)
 }
 if _,err:=signer.Check(context.Background(),crossUser);!errors.Is(err,ErrAccountDenied){
  t.Fatal("registered JTI cannot authorize different subject")
 }
 signedCorrectButUnbound:=claims
 signedCorrectButUnbound.Jti=base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77},16))
 unbound:=sign(header,signedCorrectButUnbound)
 if _,err:=signer.VerifySignature(unbound,time.Now());err!=nil{t.Fatal("cryptographic check unexpectedly failed",err)}
 if _,err:=signer.Check(context.Background(),unbound);!errors.Is(err,ErrAccountDenied){
  t.Fatal("unregistered validly signed JTI accepted")
 }
 if claims.Sub!=subject{t.Fatal("unexpected subject")}
}

func TestProductionJWTLogoutAndTokenDeactivationBothRevoke(t *testing.T){
 accounts,signer,subject,handle:=productionTokenFixture(t)
 ctx:=context.Background()
 jwt,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 claims,_:=signer.VerifySignature(jwt,time.Now())
 _,err=signer.tokens.UpdateOne(ctx,bson.D{{Key:"_id",Value:tokenID(claims.Jti)}},
  bson.D{{Key:"$set",Value:bson.D{{Key:"active",Value:false}}}})
 if err!=nil{t.Fatal(err)}
 if _,err:=signer.Check(ctx,jwt);!errors.Is(err,ErrAccountDenied){
  t.Fatal("deactivated token accepted")
 }
 second,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 digest,ok:=productionHandleDigest(handle)
 if !ok{t.Fatal("invalid internal digest")}
 if err:=accounts.sessions.Delete(ctx,"production",digest);err!=nil{t.Fatal(err)}
 if _,err:=signer.Check(ctx,second);!errors.Is(err,ErrAccountDenied){
  t.Fatal("logout/deleted session left JTI live")
 }
 if _,err:=signer.Issue(ctx,handle);!errors.Is(err,ErrAccountDenied){
  t.Fatal("deleted browser session minted another token")
 }
 version,eligible,err:=accounts.CurrentSessionVersion(ctx,"production",subject)
 if err!=nil||!eligible||version!=1{t.Fatal("logout must not suspend valid account")}
}

func TestProductionJWTConcurrentFreshnessCannotSurviveRevocation(t *testing.T){
 accounts,signer,subject,handle:=productionTokenFixture(t)
 ctx:=context.Background()
 jwt,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 const simultaneous=4
 var wg sync.WaitGroup
 begin:=make(chan struct{})
 for i:=0;i<simultaneous;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   <-begin
   _,err:=signer.Check(context.Background(),jwt)
   if err!=nil && !errors.Is(err,ErrAccountDenied)&&!errors.Is(err,ErrAccountStore){
    t.Errorf("unexpected concurrent JWT check: %v",err)
   }
  }()
 }
 close(begin)
 var revoked bool
 for i:=0;i<16;i++{
  err:=accounts.SuspendAndRevoke(ctx,subject)
  if err==nil{revoked=true;break}
  if !errors.Is(err,ErrAccountStore){t.Fatalf("invalid suspend outcome: %v",err)}
  time.Sleep(20*time.Millisecond)
 }
 wg.Wait()
 if !revoked{t.Fatal("suspension failed against concurrent checks")}
 for i:=0;i<3;i++{
  if _,err:=signer.Check(ctx,jwt);!errors.Is(err,ErrAccountDenied){
   t.Fatal("completed revocation did not deny future freshness checks",err)
  }
 }
}

func TestProductionJWTConstructorsAndMalformedHandlesFailClosed(t *testing.T){
 if _,err:=NewProductionAppTokens(context.Background(),nil,make([]byte,32));!errors.Is(err,ErrAccountDenied){
  t.Fatal("nil account source accepted")
 }
 _,signer,_,handle:=productionTokenFixture(t)
 if _,err:=NewProductionAppTokens(context.Background(),signer.accounts,make([]byte,16));!errors.Is(err,ErrAccountDenied){
  t.Fatal("bad seed accepted")
 }
 for _,bad:=range []string{"", "so1_abc", "so1_"+strings.Repeat("A",43), "so1_"+strings.Repeat("?",43),"staging_"+handle,handle+"x"}{
  if _,err:=signer.Issue(context.Background(),bad);!errors.Is(err,ErrAccountDenied){
   t.Fatalf("invalid opaque handle admitted: %q",bad)
  }
 }
 for _,jti:=range []string{"", "bad", strings.Repeat("A",129)}{
  if _,err:=signer.CheckBound(context.Background(),
   "11111111-1111-4111-8111-111111111111",1,jti);!errors.Is(err,ErrAccountDenied){
   t.Fatal("invalid JTI admitted")
  }
 }
 if _,err:=signer.Check(context.Background(),"not.a.jwt");!errors.Is(err,ErrAccountDenied){
  t.Fatal("malformed JWT admitted")
 }
 if token,err:=signer.Issue(context.Background(),handle);err!=nil || !strings.HasPrefix(token,"eyJ"){
  t.Fatal("valid handle failed",err)
 }
 var zero *ProductionAppTokens
 if _,err:=zero.JWKS();!errors.Is(err,ErrAccountDenied){t.Fatal("nil signer published JWKS")}
 if _,err:=zero.Check(context.Background(),"bad");!errors.Is(err,ErrAccountDenied){t.Fatal("nil signer admitted JWT")}
 h:=sha256.Sum256([]byte("shadowops-app-token-v1:production:bridgesquad:test"))
 if hex.EncodeToString(h[:])!=tokenID("test"){t.Fatal("missing isolated production digest domain")}
}
