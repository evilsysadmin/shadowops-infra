package production

import (
 "context"
 "encoding/json"
 "errors"
 "testing"
 "time"
)

func TestBrowserProductionMongoLoginTokenLogout(t *testing.T){
 accounts,signer,subject,_:=productionTokenFixture(t)
 h,err:=NewProductionBrowserHandler(accounts,signer,syntheticProof())
 if err!=nil{t.Fatal(err)}
 loginBody:=map[string]string{"username":"matthias","password":accountTestPass}
 data,_:=json.Marshal(loginBody)
 login:=requestBrowser(browserLoginPath,"POST",productionIssuer,string(data))
 w:=browserCall(h,login)
 if w.Code!=204||len(w.Result().Cookies())!=1{t.Fatalf("production login status %d",w.Code)}
 c:=w.Result().Cookies()[0]
 if !c.HttpOnly||!c.Secure||c.Name!=ProductionCookieName {t.Fatal("insecure browser session cookie")}
 tokenReq:=requestBrowser(browserTokenPath,"POST",Origin,"{}")
 tokenReq.AddCookie(c)
 reply:=browserCall(h,tokenReq)
 if reply.Code!=200 {t.Fatalf("production token exchange status %d",reply.Code)}
 var payload struct{Token string `json:"token"`}
 if json.Unmarshal(reply.Body.Bytes(),&payload)!=nil||payload.Token==""{t.Fatal("missing signed token")}
 claims,err:=signer.VerifySignature(payload.Token,time.Now().UTC())
 if err!=nil||claims.Sub!=subject||claims.Aud!=Audience||claims.Iss!=productionIssuer{
  t.Fatal("wrong account issuer or audience",err)
 }
 if _,err:=signer.Check(context.Background(),payload.Token);err!=nil{t.Fatal("freshness rejected valid session",err)}
 logout:=requestBrowser(browserLogoutPath,"POST",productionIssuer,"{}")
 logout.AddCookie(c)
 w=browserCall(h,logout)
 if w.Code!=204||len(w.Result().Cookies())!=1||w.Result().Cookies()[0].MaxAge!=-1{
  t.Fatal("logout did not clear authenticated browser session")
 }
 if _,err:=signer.Check(context.Background(),payload.Token);!errors.Is(err,ErrAccountDenied){
  t.Fatal("signed token survived session deletion",err)
 }
 replay:=requestBrowser(browserTokenPath,"POST",Origin,"{}")
 replay.AddCookie(c)
 if w:=browserCall(h,replay);w.Code!=401{t.Fatal("revoked cookie reused")}
}

func TestBrowserProductionConstructorRejectsMismatchedAuthorities(t *testing.T){
 accounts,tokens,_,_:=productionTokenFixture(t)
 if _,err:=NewProductionBrowserHandler(nil,tokens,syntheticProof());!errors.Is(err,ErrAccountDenied){t.Fatal("nil accounts")}
 if _,err:=NewProductionBrowserHandler(accounts,nil,syntheticProof());!errors.Is(err,ErrAccountDenied){t.Fatal("nil signer")}
 if _,err:=NewProductionBrowserHandler(accounts,tokens,"invalid");!errors.Is(err,ErrAccountDenied){t.Fatal("bad proof")}
 foreign:=*accounts
 if _,err:=NewProductionBrowserHandler(&foreign,tokens,syntheticProof());!errors.Is(err,ErrAccountDenied){
  t.Fatal("foreign signer and accounts mixed")
 }
}
