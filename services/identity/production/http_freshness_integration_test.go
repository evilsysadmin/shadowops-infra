package production

import (
 "bytes"
 "context"
 "encoding/base64"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "go.mongodb.org/mongo-driver/v2/bson"
)

func TestProductionFreshnessRealMongoAccountTokenAndSuspension(t *testing.T){
 accounts,signer,subject,handle:=productionTokenFixture(t)
 ctx:=context.Background()
 token,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 claims,err:=signer.VerifySignature(token,time.Now().UTC())
 if err!=nil{t.Fatal(err)}
 secret:=syntheticProof()
 server,err:=NewProductionFreshnessHandler(signer,secret)
 if err!=nil{t.Fatal(err)}
 request:=func(proof string)*httptest.ResponseRecorder{
  raw,_:=json.Marshal(map[string]any{
   "subject":subject,"session_version":claims.Sv,"token_jti":claims.Jti,
  })
  req:=httptest.NewRequest("POST","https://"+Host+ProductionFreshnessPath,bytes.NewReader(raw))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Authorization","Bearer "+proof)
  return invoke(server,req)
 }
 if rec:=request("soc1_wrong");rec.Code!=401{t.Fatalf("incorrect proof authorized: %d",rec.Code)}
 evidence:=request(secret)
 if evidence.Code!=200{t.Fatalf("authenticated freshness expected 200, got %d body %s",evidence.Code,evidence.Body.String())}
 var live FreshnessEvidence
 if json.Unmarshal(evidence.Body.Bytes(),&live)!=nil || live.Subject!=subject ||
  live.SessionVersion!=claims.Sv || live.TokenJTI!=claims.Jti ||
  live.Audience!=Audience || live.Issuer!=productionIssuer ||
  !live.TokenActive || !live.AccountActive || !live.SessionActive {
  t.Fatal("freshness contract does not match protected Worker")
 }
 // A valid JWT signature does not bypass account suspension.
 if err:=accounts.SuspendAndRevoke(ctx,subject);err!=nil{t.Fatal(err)}
 if _,err:=signer.VerifySignature(token,time.Now());err!=nil{t.Fatal("revoked token should still be signed")}
 if rec:=request(secret);rec.Code!=401{t.Fatalf("suspended account still authorized: %d",rec.Code)}
}

func TestProductionFreshnessLiveMongoJTIIsBoundToExactSubjectAndSession(t *testing.T){
 accounts,signer,subject,handle:=productionTokenFixture(t)
 ctx:=context.Background()
 token,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 claims,err:=signer.VerifySignature(token,time.Now())
 if err!=nil{t.Fatal(err)}
 server,err:=NewProductionFreshnessHandler(signer,syntheticProof())
 if err!=nil{t.Fatal(err)}
 makeRequest:=func(sub string,version int64,jti string)int {
  raw,_:=json.Marshal(map[string]any{
   "subject":sub,"session_version":version,"token_jti":jti,
  })
  req:=httptest.NewRequest("POST","https://"+Host+ProductionFreshnessPath,bytes.NewReader(raw))
  req.Header.Set("Authorization","Bearer "+syntheticProof())
  req.Header.Set("Content-Type","application/json")
  return invoke(server,req).Code
 }
 if got:=makeRequest("22222222-2222-4222-8222-222222222222",claims.Sv,claims.Jti);got!=401{
  t.Fatalf("subject substitution accepted: %d",got)
 }
 if got:=makeRequest(subject,claims.Sv+1,claims.Jti);got!=401{
  t.Fatalf("session version substitution accepted: %d",got)
 }
 if got:=makeRequest(subject,claims.Sv,syntheticJTI());got!=401{
  t.Fatalf("unregistered JTI accepted: %d",got)
 }
 if got:=makeRequest(subject,claims.Sv,claims.Jti);got!=200{
  t.Fatalf("real JWT binding failed: %d",got)
 }
 _,err=signer.tokens.UpdateOne(ctx,bson.D{{Key:"_id",Value:tokenID(claims.Jti)}},
  bson.D{{Key:"$set",Value:bson.D{{Key:"active",Value:false}}}})
 if err!=nil{t.Fatal(err)}
 if got:=makeRequest(subject,claims.Sv,claims.Jti);got!=401{
  t.Fatalf("deactivated JTI accepted: %d",got)
 }
 // Independent JWT issuance rebinds to a live account session; deleting the
 // latter must invalidate the new token even while its signature remains good.
 next,err:=signer.Issue(ctx,handle)
 if err!=nil{t.Fatal(err)}
 nextClaims,_:=signer.VerifySignature(next,time.Now())
 digest,ok:=productionHandleDigest(handle)
 if !ok{t.Fatal("bad test handle")}
 if err:=accounts.sessions.Delete(ctx,"production",digest);err!=nil{t.Fatal(err)}
 if got:=makeRequest(subject,nextClaims.Sv,nextClaims.Jti);got!=401{
  t.Fatalf("deleted source session still authorized: %d",got)
 }
}

func TestProductionFreshnessCannotReuseSigningSeedAsServiceProof(t *testing.T) {
 _,signer,_,_:=productionTokenFixture(t)
 if _,err:=NewProductionFreshnessHandler(signer,"soc1_"+base64.RawURLEncoding.EncodeToString(signer.private.Seed()));!errors.Is(err,ErrAccountDenied){
  t.Fatal("JWT signing seed reused as service proof")
 }
 if strings.HasPrefix(syntheticProof(),"soc1_invalid"){t.Fatal("bad synthetic credential fixture")}
 wanted:=sha256.Sum256([]byte("shadowops-consumer-v1:production:bridgesquad:"+syntheticProof()))
 actual,ok:=credentialHash(syntheticProof())
 if !ok || actual!=wanted{t.Fatal("production service secret not domain-separated")}
}
