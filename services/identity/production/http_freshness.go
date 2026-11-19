package production

// The production freshness transport is internal and deliberately not wired to
// service-production yet. It does not provide browser login or issue tokens.
import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "mime"
 "net"
 "net/http"
 "strings"
 "time"
)

const (
 ProductionFreshnessPath = "/api/identity/freshness"
 productionHTTPBodyLimit = 4096
)

type boundFreshness interface {
 CheckBound(context.Context,string,int64,string)(FreshnessEvidence,error)
 JWKS()([]byte,error)
}

// ProductionFreshnessHandler can only authorize the exact Bridge Squad
// service; the audience is never selected by a JWT or incoming request.
type ProductionFreshnessHandler struct {
 authority boundFreshness
 secretHash [32]byte
}

func credentialHash(secret string) ([32]byte,bool) {
 if len(secret)!=48 || !strings.HasPrefix(secret,"soc1_"){return [32]byte{},false}
 raw,err:=base64.RawURLEncoding.DecodeString(secret[5:])
 if err!=nil || len(raw)!=32 || base64.RawURLEncoding.EncodeToString(raw)!=secret[5:] {
  return [32]byte{},false
 }
 return sha256.Sum256([]byte("shadowops-consumer-v1:production:bridgesquad:"+secret)),true
}

// NewProductionFreshnessHandler requires a real isolated production authority.
// The service secret is supplied by private operator custody and is retained
// only as a domain-separated digest; no staging credential is accepted by name
// or inferred from frontend configuration. Never expose without TLS.
func NewProductionFreshnessHandler(authority *ProductionAppTokens,secret string)(*ProductionFreshnessHandler,error){
 if authority==nil || authority.accounts==nil ||
  authority.tokens==nil || authority.identity==nil ||
  authority.identity.Issuer()!=productionIssuer ||
  len(authority.private)!=32+32 || len(authority.public)!=32 {
  return nil,ErrAccountDenied
 }
 digest,ok:=credentialHash(secret)
 if !ok{return nil,ErrAccountDenied}
 proof,_:=base64.RawURLEncoding.DecodeString(secret[5:])
 if bytes.Equal(proof,authority.private.Seed()){return nil,ErrAccountDenied}
 return &ProductionFreshnessHandler{authority:authority,secretHash:digest},nil
}

func productionHeaders(w http.ResponseWriter) {
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("Strict-Transport-Security","max-age=31536000")
}

func productionFailure(w http.ResponseWriter,code int) {
 // No token, account ID, caller-supplied data or provider errors are echoed.
 http.Error(w,http.StatusText(code),code)
}

// ServeHTTP never accepts X-Forwarded-* as proof of TLS, hostname or client IP.
// Browser credentials are not accepted at the server-to-server freshness route.
func (h *ProductionFreshnessHandler) ServeHTTP(w http.ResponseWriter,r *http.Request){
 productionHeaders(w)
 if r==nil || r.TLS==nil || r.Host!=Host {
  productionFailure(w,http.StatusForbidden)
  return
 }
 if h==nil || h.authority==nil {
  productionFailure(w,http.StatusServiceUnavailable)
  return
 }
 if r.URL.RawQuery!="" {
  productionFailure(w,http.StatusBadRequest)
  return
 }
 if r.URL.Path=="/api/identity/jwks" && r.Method==http.MethodGet {
  if len(r.Header.Values("Cookie"))!=0 || len(r.Header.Values("Origin"))!=0 ||
   len(r.Header.Values("Authorization"))!=0 {
   productionFailure(w,http.StatusForbidden)
   return
  }
  keys,err:=h.authority.JWKS()
  if err!=nil || len(keys)==0 || len(keys)>8192 {
   productionFailure(w,http.StatusServiceUnavailable)
   return
  }
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write(keys)
  return
 }
 if r.URL.Path!="/api/identity/freshness" {
  if r.URL.Path=="/readyz" || r.URL.Path=="/login" ||
   strings.HasPrefix(r.URL.Path,"/api/identity/"){
   productionFailure(w,http.StatusServiceUnavailable)
  }else{
   http.NotFound(w,r)
  }
  return
 }
 if r.Method!=http.MethodPost {
  w.Header().Set("Allow","POST")
  productionFailure(w,http.StatusMethodNotAllowed)
  return
 }
 if len(r.Header.Values("Origin"))!=0 || len(r.Header.Values("Cookie"))!=0 ||
  len(r.Header.Values("Referer"))!=0 || len(r.Header.Values("Sec-Fetch-Site"))!=0 {
  productionFailure(w,http.StatusForbidden)
  return
 }
 peer,_,err:=net.SplitHostPort(r.RemoteAddr)
 if err!=nil || net.ParseIP(peer)==nil {
  productionFailure(w,http.StatusForbidden)
  return
 }
 auth:=r.Header.Values("Authorization")
 if len(auth)!=1 {
  productionFailure(w,http.StatusUnauthorized)
  return
 }
 credential,ok:=strings.CutPrefix(auth[0],"Bearer ")
 digest,canonical:=credentialHash(credential)
 if !ok || !canonical || subtle.ConstantTimeCompare(digest[:],h.secretHash[:])!=1 {
  productionFailure(w,http.StatusUnauthorized)
  return
 }
 if len(r.Header.Values("Content-Type"))!=1 || r.Header.Get("Content-Encoding")!="" {
  productionFailure(w,http.StatusUnsupportedMediaType)
  return
 }
 media,params,err:=mime.ParseMediaType(r.Header.Get("Content-Type"))
 if err!=nil || media!="application/json" || len(params)!=0 {
  productionFailure(w,http.StatusUnsupportedMediaType)
  return
 }
 if r.Body==nil {
  productionFailure(w,http.StatusBadRequest)
  return
 }
 raw,err:=io.ReadAll(io.LimitReader(r.Body,productionHTTPBodyLimit+1))
 if err!=nil {
  productionFailure(w,http.StatusBadRequest)
  return
 }
 if len(raw)>productionHTTPBodyLimit {
  productionFailure(w,http.StatusRequestEntityTooLarge)
  return
 }
 var payload struct {
  Subject string `json:"subject"`
  SessionVersion int64 `json:"session_version"`
  TokenJTI string `json:"token_jti"`
 }
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 if decoder.Decode(&payload)!=nil || decoder.Decode(new(any))!=io.EOF ||
  !sessionSubjectPattern.MatchString(payload.Subject) ||
  payload.SessionVersion<1 || payload.SessionVersion>1<<62 ||
  len(payload.TokenJTI)!=22 {
  productionFailure(w,http.StatusBadRequest)
  return
 }
 nonce,err:=decodeCanonical(payload.TokenJTI,16)
 if err!=nil || len(nonce)!=16 {
  productionFailure(w,http.StatusBadRequest)
  return
 }
 ctx,cancel:=context.WithTimeout(r.Context(),2500*time.Millisecond)
 defer cancel()
 evidence,err:=h.authority.CheckBound(ctx,payload.Subject,payload.SessionVersion,payload.TokenJTI)
 if err!=nil {
  if errors.Is(err,ErrAccountDenied) {
   productionFailure(w,http.StatusUnauthorized)
  }else{
   productionFailure(w,http.StatusServiceUnavailable)
  }
  return
 }
 if evidence.Issuer!=productionIssuer || evidence.Audience!=Audience ||
  evidence.Subject!=payload.Subject || evidence.SessionVersion!=payload.SessionVersion ||
  evidence.TokenJTI!=payload.TokenJTI || !evidence.AccountActive ||
  !evidence.SessionActive || !evidence.TokenActive ||
  evidence.CheckedAt<=0 {
  productionFailure(w,http.StatusServiceUnavailable)
  return
 }
 w.Header().Set("Content-Type","application/json")
 if err:=json.NewEncoder(w).Encode(evidence);err!=nil{
  return
 }
}
