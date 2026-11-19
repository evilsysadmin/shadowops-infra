package production

// Opt-in production browser transport. Neither this handler nor the native
// account authority is wired to cmd/service-production in this milestone.
import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "io"
 "mime"
 "net"
 "net/http"
 "strings"
 "sync"
 "time"
)

const (
 ProductionCookieName = "__Host-shadowops_sso_production"
 browserLoginPath = "/api/identity/login"
 browserLogoutPath = "/api/identity/logout"
 browserTokenPath = "/api/identity/token"
 browserAssetPath = "/assets/login-production.js"
)

type productionLogin interface {
 Issue(context.Context,string,string)(string,error)
 Logout(context.Context,string)error
}
type productionTokenIssuer interface {
 Issue(context.Context,string)(string,error)
}
type ProductionBrowserHandler struct {
 accounts productionLogin
 tokens productionTokenIssuer
 freshness http.Handler
 limits browserThrottle
 kdf chan struct{}
}

// NewProductionBrowserHandler refuses a mix of different production
// authorities. The service credential must already be under independent
// operator custody and cannot be inferred from the frontend.
func NewProductionBrowserHandler(accounts *AccountAuthority,tokens *ProductionAppTokens,secret string)(*ProductionBrowserHandler,error){
 if accounts==nil || tokens==nil || tokens.accounts!=accounts {
  return nil,ErrAccountDenied
 }
 fresh,err:=NewProductionFreshnessHandler(tokens,secret)
 if err!=nil{return nil,err}
 return &ProductionBrowserHandler{accounts:accounts,tokens:tokens,freshness:fresh,kdf:make(chan struct{},2)},nil
}

type browserCounter struct {minute time.Time; total,logins int}
type browserThrottle struct{
 mu sync.Mutex
 peers map[string]browserCounter
 global browserCounter
}
func (b *browserThrottle) allow(peer string,login bool,now time.Time)bool{
 b.mu.Lock()
 defer b.mu.Unlock()
 if b.peers==nil {b.peers=make(map[string]browserCounter)}
 if now.Sub(b.global.minute)>=time.Minute{
  b.global=browserCounter{minute:now}
  for ip,entry:=range b.peers {if now.Sub(entry.minute)>=time.Minute{delete(b.peers,ip)}}
 }
 val,exists:=b.peers[peer]
 if !exists && len(b.peers)>=512{return false}
 if now.Sub(val.minute)>=time.Minute{val=browserCounter{minute:now}}
 if val.total>=120 || b.global.total>=600 || (login && (val.logins>=8 || b.global.logins>=50)){
  return false
 }
 val.total++;b.global.total++
 if login{val.logins++;b.global.logins++}
 b.peers[peer]=val
 return true
}

func productionCookie(w http.ResponseWriter,handle string,clear bool){
 c:=&http.Cookie{Name:ProductionCookieName,Value:handle,Path:"/",
  Secure:true,HttpOnly:true,SameSite:http.SameSiteNoneMode}
 if clear{
  c.MaxAge=-1
  c.Expires=time.Unix(1,0).UTC()
 }
 http.SetCookie(w,c)
}
func productionReadCookie(r *http.Request)(string,bool){
 count:=0
 var handle string
 for _,c:=range r.Cookies(){
  if c.Name==ProductionCookieName{count++;handle=c.Value}
 }
 if count!=1{return "",false}
 if _,ok:=productionHandleDigest(handle);!ok{return "",false}
 return handle,true
}
func productionJSON(w http.ResponseWriter,r *http.Request,target any)bool{
 if r.Body==nil{return false}
 raw,err:=io.ReadAll(io.LimitReader(r.Body,4097))
 if err!=nil || len(raw)==0 || len(raw)>4096 || raw[0]!='{'{return false}
 d:=json.NewDecoder(bytes.NewReader(raw))
 d.DisallowUnknownFields()
 return d.Decode(target)==nil && d.Decode(new(any))==io.EOF
}
func browserError(w http.ResponseWriter,err error){
 if errors.Is(err,ErrAccountDenied){productionFailure(w,http.StatusUnauthorized);return}
 productionFailure(w,http.StatusServiceUnavailable)
}

// Only the production origin may mutate its browser session. The one
// explicitly authorized game origin may exchange an existing cookie for a
// short-lived token. Request bodies cannot select other audiences.
func (h *ProductionBrowserHandler) ServeHTTP(w http.ResponseWriter,r *http.Request){
 productionHeaders(w)
 w.Header().Set("Vary","Origin")
 if r==nil || r.TLS==nil || r.Host!=Host {
  productionFailure(w,http.StatusForbidden);return
 }
 if h==nil || h.accounts==nil || h.tokens==nil || h.freshness==nil {
  productionFailure(w,http.StatusServiceUnavailable);return
 }
 if r.URL.Path==ProductionFreshnessPath || r.URL.Path=="/api/identity/jwks"{
  h.freshness.ServeHTTP(w,r)
  return
 }
 if r.URL.Path=="/login" || r.URL.Path==browserAssetPath {
  serveProductionLogin(w,r);return
 }
 if r.URL.Path=="/readyz" || r.URL.Path=="/api/identity/register" ||
  r.URL.Path=="/api/identity/recover" || r.URL.Path=="/api/identity/refresh" {
  productionFailure(w,http.StatusServiceUnavailable);return
 }
 if r.URL.Path!=browserLoginPath && r.URL.Path!=browserLogoutPath &&
  r.URL.Path!=browserTokenPath {
  http.NotFound(w,r);return
 }
 if r.URL.RawQuery!="" || len(r.Header.Values("Authorization"))!=0 {
  productionFailure(w,http.StatusBadRequest);return
 }
 origin:=r.Header.Values("Origin")
 allowed:=productionIssuer
 if r.URL.Path==browserTokenPath{allowed=Origin}
 // JSON-only POST + same-origin login/logout prevents CSRF. The Bridge
 // Squad token exchange requires CORS with credentials, never wildcard.
 if r.Method==http.MethodOptions && r.URL.Path==browserTokenPath{
  if len(origin)!=1 || origin[0]!=Origin ||
   len(r.Header.Values("Cookie"))!=0 ||
   r.Header.Get("Access-Control-Request-Method")!="POST" ||
   !strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Request-Headers")),"content-type") {
   productionFailure(w,http.StatusForbidden);return
  }
  w.Header().Set("Access-Control-Allow-Origin",Origin)
  w.Header().Set("Access-Control-Allow-Credentials","true")
  w.Header().Set("Access-Control-Allow-Methods","POST")
  w.Header().Set("Access-Control-Allow-Headers","Content-Type")
  w.WriteHeader(http.StatusNoContent)
  return
 }
 if len(origin)!=1 || origin[0]!=allowed ||
  r.Header.Get("Sec-Fetch-Site")=="cross-site" && r.URL.Path!=browserTokenPath {
  productionFailure(w,http.StatusForbidden);return
 }
 if r.Method!=http.MethodPost{
  w.Header().Set("Allow","POST")
  productionFailure(w,http.StatusMethodNotAllowed);return
 }
 peer,_,err:=net.SplitHostPort(r.RemoteAddr)
 if err!=nil || net.ParseIP(peer)==nil ||
  !h.limits.allow(peer,r.URL.Path==browserLoginPath,time.Now()){
  w.Header().Set("Retry-After","60")
  productionFailure(w,http.StatusTooManyRequests);return
 }
 if len(r.Header.Values("Content-Type"))!=1 ||
  r.Header.Get("Content-Encoding")!="" {
  productionFailure(w,http.StatusUnsupportedMediaType);return
 }
 media,params,err:=mime.ParseMediaType(r.Header.Get("Content-Type"))
 if err!=nil || media!="application/json" || len(params)!=0{
  productionFailure(w,http.StatusUnsupportedMediaType);return
 }
 if r.URL.Path==browserTokenPath {
  w.Header().Set("Access-Control-Allow-Origin",Origin)
  w.Header().Set("Access-Control-Allow-Credentials","true")
 }
 ctx,cancel:=context.WithTimeout(r.Context(),5*time.Second)
 defer cancel()
 switch r.URL.Path{
 case browserLoginPath:
  var body struct {
   Username string `json:"username"`
   Password string `json:"password"`
  }
  if !productionJSON(w,r,&body) || !accountAlias.MatchString(body.Username) ||
   len(body.Password)==0 || len(body.Password)>4096 {
   productionFailure(w,http.StatusBadRequest);return
  }
  // Argon2id is memory-intensive: cap simultaneous KDF operations in
  // addition to IP/global request limits, including when login races occur.
  if h.kdf==nil{productionFailure(w,http.StatusServiceUnavailable);return}
  select {
  case h.kdf<-struct{}{}:
   defer func(){<-h.kdf}()
  default:
   w.Header().Set("Retry-After","60")
   productionFailure(w,http.StatusTooManyRequests);return
  }
  handle,err:=h.accounts.Issue(ctx,body.Username,body.Password)
  if err!=nil{browserError(w,err);return}
  if _,ok:=productionHandleDigest(handle);!ok {
   productionFailure(w,http.StatusServiceUnavailable);return
  }
  productionCookie(w,handle,false)
  w.WriteHeader(http.StatusNoContent)
 case browserTokenPath:
  var empty struct{}
  if !productionJSON(w,r,&empty){
   productionFailure(w,http.StatusBadRequest);return
  }
  handle,ok:=productionReadCookie(r)
  if !ok{productionFailure(w,http.StatusUnauthorized);return}
  token,err:=h.tokens.Issue(ctx,handle)
  if err!=nil{browserError(w,err);return}
  if len(token)<50 || len(token)>8192{
   productionFailure(w,http.StatusServiceUnavailable);return
  }
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(struct{Token string `json:"token"`}{Token:token})
 case browserLogoutPath:
  var empty struct{}
  if !productionJSON(w,r,&empty){productionFailure(w,http.StatusBadRequest);return}
  handle,ok:=productionReadCookie(r)
  if !ok{productionFailure(w,http.StatusUnauthorized);return}
  if err:=h.accounts.Logout(ctx,handle);err!=nil{browserError(w,err);return}
  productionCookie(w,"",true)
  w.WriteHeader(http.StatusNoContent)
 }
}

const prodLoginReturn = Origin + "/?shadowops=central"
const productionLoginHTML = `<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShadowOps ID · Bridge Squad</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#101914;color:#f6eedb;font:16px system-ui;min-height:100vh;display:grid;place-items:center}
main{width:min(94vw,440px);border:1px solid #536a52;background:#1b2b22;padding:2rem;border-radius:19px;box-shadow:0 16px 70px #0006}
h1{font-size:1.55rem}label{display:block;margin:1rem 0 .4rem}input{font:inherit;width:100%;padding:12px;border:1px solid #819480;background:#101914;color:#fff;border-radius:8px}
button,.return-link{display:block;text-align:center;width:100%;margin-top:1rem;padding:13px;border-radius:8px;font:inherit;text-decoration:none}
button{cursor:pointer;background:#dec48d;color:#152118;border:0;font-weight:650}.return-link{color:#dec48d;border:1px solid #5b7258}
small{color:#aebfae}p{line-height:1.5}a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid #dec48d;outline-offset:3px}
</style><script src="/assets/login-production.js" defer></script>
</head><body data-return-url="` + prodLoginReturn + `">
<main><a class="brand" href="` + prodLoginReturn + `">SHADOWOPS ID</a>
<h1>Entrar en Bridge Squad</h1><p>Identifícate con una cuenta de producción de ShadowOps ID.</p>
<form id="access-form">
<label for="username">Usuario</label><input id="username" name="username" autocomplete="username" pattern="[a-z][a-z0-9_]{2,31}" minlength="3" maxlength="32" required>
<label for="password">Contraseña</label><input type="password" id="password" name="password" autocomplete="current-password" maxlength="4096" required>
<button id="submit" type="submit">Entrar y continuar</button>
</form><p id="status" role="status" aria-live="polite"></p>
<a class="return-link" href="` + prodLoginReturn + `">Volver a Bridge Squad</a>
<small>Acceso protegido · No se reutilizan cuentas de staging.</small></main></body></html>`
const productionLoginJS = `'use strict';
const form=document.querySelector('#access-form');
const status=document.querySelector('#status');
const submit=document.querySelector('#submit');
form.addEventListener('submit',async event=>{
 event.preventDefault();
 if(submit.disabled||!form.reportValidity())return;
 submit.disabled=true;status.textContent='Comprobando tus credenciales…';
 try{
  const response=await fetch('/api/identity/login',{
   method:'POST',credentials:'same-origin',redirect:'error',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({username:document.querySelector('#username').value,password:document.querySelector('#password').value}),
   signal:AbortSignal.timeout(10000)
  });
  if(!response.ok){status.textContent=response.status===429?'Demasiados intentos. Inténtalo en un minuto.':'Acceso no autorizado o servicio temporalmente no disponible.';return;}
  location.replace(document.body.dataset.returnUrl);
 }catch{status.textContent='No se ha podido conectar con ShadowOps ID.';}
 finally{document.querySelector('#password').value='';submit.disabled=false;}
});`

func serveProductionLogin(w http.ResponseWriter,r *http.Request){
 if r.Method!=http.MethodGet{
  w.Header().Set("Allow","GET")
  productionFailure(w,http.StatusMethodNotAllowed);return
 }
 w.Header().Set("Content-Security-Policy",
  "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "+
   "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
 if r.URL.Path=="/login"{
  if r.URL.RawQuery!="app=bridgesquad"{
   productionFailure(w,http.StatusBadRequest);return
  }
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  _,_=io.WriteString(w,productionLoginHTML);return
 }
 if r.URL.RawQuery!=""{productionFailure(w,http.StatusBadRequest);return}
 w.Header().Set("Content-Type","text/javascript; charset=utf-8")
 _,_=io.WriteString(w,productionLoginJS)
}
