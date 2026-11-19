package production

// Production JWT issuance is internal only. No HTTP token or freshness route
// exists until the independently authenticated production service is deployed.
import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "strings"
 "time"

 "github.com/evilsysadmin/shadowops-infra/services/identity/core"
 "github.com/evilsysadmin/shadowops-infra/services/identity/session"
 "go.mongodb.org/mongo-driver/v2/bson"
 "go.mongodb.org/mongo-driver/v2/mongo"
 "go.mongodb.org/mongo-driver/v2/mongo/options"
 "go.mongodb.org/mongo-driver/v2/mongo/readconcern"
 "go.mongodb.org/mongo-driver/v2/mongo/readpref"
 "go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

const (
 productionTokenCollection = "production_application_tokens"
 productionTokenLifetime = 2*time.Minute
 productionFreshnessDeadline = 2*time.Second
 productionIssuer = "https://id.shadowops.dpdns.org"
)

type ProductionAppTokens struct {
 accounts *AccountAuthority
 tokens *mongo.Collection
 identity *core.Core
 private ed25519.PrivateKey
 public ed25519.PublicKey
 kid string
}

type AppClaims struct {
 Iss string `json:"iss"`
 Aud string `json:"aud"`
 Sub string `json:"sub"`
 Iat int64 `json:"iat"`
 Nbf int64 `json:"nbf"`
 Exp int64 `json:"exp"`
 Sv int64 `json:"sv"`
 Jti string `json:"jti"`
}

type signedHeader struct {
 Alg string `json:"alg"`
 Typ string `json:"typ"`
 Kid string `json:"kid"`
}

type tokenBinding struct {
 ID string `bson:"_id"`
 Issuer string `bson:"issuer"`
 Audience string `bson:"audience"`
 Subject string `bson:"subject"`
 SessionVersion int64 `bson:"session_version"`
 SessionDigest string `bson:"session_digest"`
 IssuedAt time.Time `bson:"issued_at"`
 ExpiresAt time.Time `bson:"expires_at"`
 Active bool `bson:"active"`
}

type FreshnessEvidence struct {
 Issuer string `json:"issuer"`
 Audience string `json:"audience"`
 Subject string `json:"subject"`
 SessionVersion int64 `json:"session_version"`
 TokenJTI string `json:"token_jti"`
 CheckedAt int64 `json:"checked_at"`
 AccountActive bool `json:"account_active"`
 SessionActive bool `json:"session_active"`
 TokenActive bool `json:"token_active"`
}

// NewProductionAppTokens accepts a production-only account authority and
// independent signing seed. This is NOT equivalent to a validated Vault binding;
// production TLS, Mongo RBAC and secret custody remain deployment prerequisites.
func NewProductionAppTokens(ctx context.Context, accounts *AccountAuthority, seed []byte) (*ProductionAppTokens,error) {
 if accounts==nil || !accounts.ready(ctx) || len(seed)!=ed25519.SeedSize {
  return nil,ErrAccountDenied
 }
 identity,err:=core.New("production",seed)
 if err!=nil || identity.Issuer()!=productionIssuer{return nil,ErrAccountDenied}
 keys,err:=identity.JWKS()
 if err!=nil{return nil,ErrAccountStore}
 var jwks core.KeySet
 if json.Unmarshal(keys,&jwks)!=nil || len(jwks.Keys)!=1 || jwks.Keys[0].Kid=="" {return nil,ErrAccountStore}
 col:=accounts.client.Database(Database).Collection(productionTokenCollection,options.Collection().
  SetReadConcern(readconcern.Majority()).SetReadPreference(readpref.Primary()).
  SetWriteConcern(writeconcern.Majority()))
 _,err=col.Indexes().CreateOne(ctx,mongo.IndexModel{
  Keys:bson.D{{Key:"expires_at",Value:1}},
  Options:options.Index().SetName("production_application_token_ttl").SetExpireAfterSeconds(0),
 })
 if err!=nil{return nil,ErrAccountStore}
 key:=ed25519.NewKeyFromSeed(seed)
 return &ProductionAppTokens{accounts:accounts,tokens:col,identity:identity,private:key,
  public:key.Public().(ed25519.PublicKey),kid:jwks.Keys[0].Kid},nil
}

func tokenID(jti string) string {
 digest:=sha256.Sum256([]byte("shadowops-app-token-v1:production:bridgesquad:"+jti))
 return hex.EncodeToString(digest[:])
}

func decodeCanonical(s string, max int) ([]byte,error) {
 if s=="" || len(s)>2*max {return nil,ErrAccountDenied}
 data,err:=base64.RawURLEncoding.DecodeString(s)
 if err!=nil || len(data)>max || base64.RawURLEncoding.EncodeToString(data)!=s{return nil,ErrAccountDenied}
 return data,nil
}

func productionHandleDigest(handle string) ([32]byte,bool) {
 if len(handle)!=47 || !strings.HasPrefix(handle,"so1_"){return [32]byte{},false}
 raw,err:=decodeCanonical(handle[4:],32)
 if err!=nil || len(raw)!=32{return [32]byte{},false}
 return sha256.Sum256(append([]byte("shadowops-session-v1:production:"),raw...)),true
}

// Issue requires an existing authenticated opaque session. It fences the
// exact active account and persists a token->session digest binding in the
// same snapshot/majority transaction before signing the two-minute JWT.
func (p *ProductionAppTokens) Issue(ctx context.Context,handle string) (string,error) {
 if p==nil || p.accounts==nil || !p.accounts.ready(ctx) || p.tokens==nil ||
  len(p.private)!=ed25519.PrivateKeySize || ctx==nil || ctx.Err()!=nil{return "",ErrAccountDenied}
 digest,ok:=productionHandleDigest(handle)
 if !ok{return "",ErrAccountDenied}
 var nonce [16]byte
 if _,err:=rand.Read(nonce[:]);err!=nil{return "",ErrAccountStore}
 jti:=base64.RawURLEncoding.EncodeToString(nonce[:])
 tx,err:=p.accounts.client.StartSession()
 if err!=nil{return "",ErrAccountStore}
 defer tx.EndSession(context.Background())
 config:=options.Transaction().SetReadConcern(readconcern.Snapshot()).
  SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
 var claims AppClaims
 _,err=tx.WithTransaction(ctx,func(tctx context.Context)(any,error){
  rec,found,err:=p.accounts.sessions.Get(tctx,"production",digest)
  if err!=nil{return nil,err}
  now:=time.Now().UTC()
  if !found || rec.Digest!=digest || rec.Environment!="production" ||
   !sessionSubjectPattern.MatchString(rec.Subject) || rec.SessionVersion<1 ||
   !rec.IssuedAt.Before(rec.ExpiresAt) || rec.IssuedAt.After(now.Add(30*time.Second)) ||
   rec.ExpiresAt.Sub(rec.IssuedAt)>session.Lifetime || !now.Before(rec.ExpiresAt) {
   return nil,ErrAccountDenied
  }
  filter:=append(activeAccountFilter(),
   bson.E{Key:"_id",Value:rec.Subject},bson.E{Key:"session_version",Value:rec.SessionVersion})
  update,err:=p.accounts.accounts.UpdateOne(tctx,filter,bson.D{
   {Key:"$inc",Value:bson.D{{Key:"login_fence",Value:int64(1)}}},
  })
  if err!=nil{return nil,err}
  if update.ModifiedCount!=1{return nil,ErrAccountDenied}
  expires:=now.Add(productionTokenLifetime)
  if rec.ExpiresAt.Before(expires){expires=rec.ExpiresAt}
  if expires.Unix()<=now.Unix(){return nil,ErrAccountDenied}
  claims=AppClaims{Iss:productionIssuer,Aud:Audience,Sub:rec.Subject,
   Iat:now.Unix(),Nbf:now.Unix(),Exp:expires.Unix(),Sv:rec.SessionVersion,Jti:jti}
  _,err=p.tokens.InsertOne(tctx,tokenBinding{
   ID:tokenID(jti),Issuer:claims.Iss,Audience:claims.Aud,
   Subject:claims.Sub,SessionVersion:claims.Sv,
   SessionDigest:hex.EncodeToString(digest[:]),
   IssuedAt:time.Unix(claims.Iat,0).UTC(),ExpiresAt:time.Unix(claims.Exp,0).UTC(),
   Active:true,
  })
  return nil,err
 },config)
 if err!=nil{
  if errors.Is(err,ErrAccountDenied)||errors.Is(err,mongo.ErrNoDocuments){return "",ErrAccountDenied}
  return "",ErrAccountStore
 }
 header,_:=json.Marshal(signedHeader{Alg:"EdDSA",Typ:"JWT",Kid:p.kid})
 body,_:=json.Marshal(claims)
 message:=base64.RawURLEncoding.EncodeToString(header)+"."+base64.RawURLEncoding.EncodeToString(body)
 return message+"."+base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.private,[]byte(message))),nil
}

func (p *ProductionAppTokens) JWKS() ([]byte,error) {
 if p==nil || p.identity==nil || p.identity.Issuer()!=productionIssuer {return nil,ErrAccountDenied}
 return p.identity.JWKS()
}

// VerifySignature checks cryptographic and JWT claims, NOT account freshness.
// Every protected operation must additionally perform an authoritative check.
func (p *ProductionAppTokens) VerifySignature(raw string,now time.Time)(AppClaims,error){
 var zero AppClaims
 if p==nil || len(p.public)!=ed25519.PublicKeySize || p.kid=="" ||
  len(raw)>8192 || now.IsZero(){return zero,ErrAccountDenied}
 parts:=strings.Split(raw,".")
 if len(parts)!=3{return zero,ErrAccountDenied}
 hb,err:=decodeCanonical(parts[0],512);if err!=nil{return zero,ErrAccountDenied}
 cb,err:=decodeCanonical(parts[1],2048);if err!=nil{return zero,ErrAccountDenied}
 sig,err:=decodeCanonical(parts[2],64)
 if err!=nil || len(sig)!=ed25519.SignatureSize ||
  !ed25519.Verify(p.public,[]byte(parts[0]+"."+parts[1]),sig){return zero,ErrAccountDenied}
 var header signedHeader
 decoder:=json.NewDecoder(bytes.NewReader(hb));decoder.DisallowUnknownFields()
 if decoder.Decode(&header)!=nil || decoder.Decode(new(any))!=io.EOF ||
  header.Alg!="EdDSA" || header.Typ!="JWT" || header.Kid!=p.kid{return zero,ErrAccountDenied}
 var claims AppClaims
 decoder=json.NewDecoder(bytes.NewReader(cb));decoder.DisallowUnknownFields()
 if decoder.Decode(&claims)!=nil || decoder.Decode(new(any))!=io.EOF{return zero,ErrAccountDenied}
 stamp:=now.UTC().Unix()
 if claims.Iss!=productionIssuer || claims.Aud!=Audience ||
  !sessionSubjectPattern.MatchString(claims.Sub) || claims.Sv<1 ||
  claims.Iat<=0 || claims.Iat>stamp+5 || claims.Nbf>stamp+5 ||
  claims.Nbf<claims.Iat-5 || claims.Exp<=stamp || claims.Exp<=claims.Iat ||
  claims.Exp-claims.Iat>int64(productionTokenLifetime.Seconds()) {return zero,ErrAccountDenied}
 nonce,err:=decodeCanonical(claims.Jti,16)
 if err!=nil || len(nonce)!=16{return zero,ErrAccountDenied}
 return claims,nil
}

// Check verifies the JWT itself AND its live account, session and JTI state.
func (p *ProductionAppTokens) Check(ctx context.Context,jwt string)(FreshnessEvidence,error){
 if ctx==nil || ctx.Err()!=nil{return FreshnessEvidence{},ErrAccountDenied}
 claims,err:=p.VerifySignature(jwt,time.Now().UTC())
 if err!=nil{return FreshnessEvidence{},ErrAccountDenied}
 return p.CheckBound(ctx,claims.Sub,claims.Sv,claims.Jti)
}

// CheckBound is an INTERNAL primitive. Future HTTP callers MUST authenticate
// their fixed production Bridge Squad service proof and must bind the decoded
// and independently VERIFIED JWT claims. Never expose this as a public query.
func (p *ProductionAppTokens) CheckBound(ctx context.Context,subject string,version int64,jti string)(FreshnessEvidence,error){
 var denied FreshnessEvidence
 if p==nil || p.accounts==nil || !p.accounts.ready(ctx) || p.tokens==nil ||
  ctx==nil || ctx.Err()!=nil || !sessionSubjectPattern.MatchString(subject) || version<1 {
  return denied,ErrAccountDenied
 }
 nonce,err:=decodeCanonical(jti,16)
 if err!=nil || len(nonce)!=16{return denied,ErrAccountDenied}
 ctx,cancel:=context.WithTimeout(ctx,productionFreshnessDeadline)
 defer cancel()
 tx,err:=p.accounts.client.StartSession()
 if err!=nil{return denied,ErrAccountStore}
 defer tx.EndSession(context.Background())
 config:=options.Transaction().SetReadConcern(readconcern.Snapshot()).
  SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary())
 var checked,expiration time.Time
 _,err=tx.WithTransaction(ctx,func(tctx context.Context)(any,error){
  checked=time.Now().UTC()
  var binding tokenBinding
  if err:=p.tokens.FindOne(tctx,bson.D{{Key:"_id",Value:tokenID(jti)}}).Decode(&binding);err!=nil{return nil,err}
  if binding.ID!=tokenID(jti) || binding.Issuer!=productionIssuer ||
   binding.Audience!=Audience || binding.Subject!=subject || binding.SessionVersion!=version ||
   !binding.Active || binding.IssuedAt.After(checked) || !checked.Before(binding.ExpiresAt) ||
   !binding.IssuedAt.Before(binding.ExpiresAt) ||
   binding.ExpiresAt.Sub(binding.IssuedAt)>productionTokenLifetime{return nil,ErrAccountDenied}
  data,err:=hex.DecodeString(binding.SessionDigest)
  if err!=nil || len(data)!=32 || hex.EncodeToString(data)!=binding.SessionDigest{return nil,ErrAccountDenied}
  var digest [32]byte
  copy(digest[:],data)
  rec,found,err:=p.accounts.sessions.Get(tctx,"production",digest)
  if err!=nil{return nil,err}
  if !found || rec.Subject!=subject || rec.SessionVersion!=version ||
   rec.Environment!="production" || rec.Digest!=digest ||
   !rec.IssuedAt.Before(rec.ExpiresAt) || rec.IssuedAt.After(checked.Add(30*time.Second)) ||
   rec.ExpiresAt.Sub(rec.IssuedAt)>session.Lifetime || !checked.Before(rec.ExpiresAt) ||
   binding.ExpiresAt.After(rec.ExpiresAt) {return nil,ErrAccountDenied}
  fences:=[]struct{col *mongo.Collection;filter bson.D}{
   {p.accounts.accounts,append(activeAccountFilter(),
    bson.E{Key:"_id",Value:subject},bson.E{Key:"session_version",Value:version})},
   {p.accounts.client.Database(Database).Collection(sessionCollectionName),
    bson.D{{Key:"environment",Value:"production"}, {Key:"digest",Value:binding.SessionDigest},
     {Key:"subject",Value:subject},{Key:"session_version",Value:version},
     {Key:"expires_at",Value:bson.D{{Key:"$gt",Value:checked}}}}},
   {p.tokens,bson.D{{Key:"_id",Value:binding.ID},{Key:"active",Value:true}}},
  }
  for _,fence:=range fences{
   result,err:=fence.col.UpdateOne(tctx,fence.filter,
    bson.D{{Key:"$inc",Value:bson.D{{Key:"freshness_fence",Value:int64(1)}}}})
   if err!=nil{return nil,err}
   if result.ModifiedCount!=1{return nil,ErrAccountDenied}
  }
  expiration=binding.ExpiresAt
  return nil,nil
 },config)
 if err!=nil{
  if errors.Is(err,ErrAccountDenied)||errors.Is(err,mongo.ErrNoDocuments){return denied,ErrAccountDenied}
  return denied,ErrAccountStore
 }
 end:=time.Now().UTC()
 if ctx.Err()!=nil || end.Before(checked) || end.Sub(checked)>productionFreshnessDeadline ||
  !end.Before(expiration){return denied,ErrAccountStore}
 return FreshnessEvidence{Issuer:productionIssuer,Audience:Audience,Subject:subject,
  SessionVersion:version,TokenJTI:jti,CheckedAt:checked.Unix(),
  AccountActive:true,SessionActive:true,TokenActive:true},nil
}
