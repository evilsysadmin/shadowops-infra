package production

import (
 "bytes"
 "context"
 "crypto/tls"
 "encoding/base64"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

type fakeBrowserAccount struct{ logins,logouts int; issueErr,logoutErr error; handle string }
func (a *fakeBrowserAccount) Issue(_ context.Context,user,password string)(string,error){
 a.logins++
 if a.issueErr!=nil{return "",a.issueErr}
 if user!="matthias" || password!="correct-password" {return "",ErrAccountDenied}
 return a.handle,nil
}
func (a *fakeBrowserAccount) Logout(_ context.Context,handle string)error{
 a.logouts++
 if a.logoutErr!=nil{return a.logoutErr}
 if handle!=a.handle{return ErrAccountDenied}
 return nil
}
type fakeBrowserToken struct{ calls int; token string; error error }
func (f *fakeBrowserToken) Issue(_ context.Context,handle string)(string,error){
 f.calls++
 return f.token,f.error
}
type fakeFreshnessHTTP struct{calls int}
func (f *fakeFreshnessHTTP) ServeHTTP(w http.ResponseWriter,r *http.Request){
 f.calls++;w.WriteHeader(http.StatusNoContent)
}
func setupBrowser()(*ProductionBrowserHandler,*fakeBrowserAccount,*fakeBrowserToken,*fakeFreshnessHTTP){
 a:=&fakeBrowserAccount{handle:"so1_"+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x37},32))}
 tok:=&fakeBrowserToken{token:strings.Repeat("a",90)}
 f:=&fakeFreshnessHTTP{}
 return &ProductionBrowserHandler{accounts:a,tokens:tok,freshness:f,kdf:make(chan struct{},2)},a,tok,f
}
func requestBrowser(path,method,origin,body string)*http.Request{
 r:=httptest.NewRequest(method,"https://"+Host+path,strings.NewReader(body))
 r.Host=Host;r.TLS=&tls.ConnectionState{}
 if origin!=""{r.Header.Set("Origin",origin)}
 if method=="POST"{r.Header.Set("Content-Type","application/json")}
 return r
}
func browserCall(h *ProductionBrowserHandler,r *http.Request)*httptest.ResponseRecorder{
 w:=httptest.NewRecorder();h.ServeHTTP(w,r);return w
}
func TestProductionLoginCookieAndLogoutHTTPContract(t *testing.T){
 h,account,tokens,_:=setupBrowser()
 login:=requestBrowser(browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password"}`)
 w:=browserCall(h,login)
 if w.Code!=204 || account.logins!=1 || len(w.Result().Cookies())!=1{t.Fatalf("login status %d",w.Code)}
 c:=w.Result().Cookies()[0]
 if c.Name!=ProductionCookieName || c.Value!=account.handle || !c.Secure ||
  !c.HttpOnly || c.Path!="/" || c.Domain!="" || c.SameSite!=http.SameSiteNoneMode{
  t.Fatal("login did not set secure host-only production cookie")
 }
 if strings.Contains(w.Body.String(),"so1_"){t.Fatal("handle leaked in response")}
 tokenRequest:=requestBrowser(browserTokenPath,"POST",Origin,"{}")
 tokenRequest.AddCookie(c)
 got:=browserCall(h,tokenRequest)
 var payload struct{Token string `json:"token"` }
 if got.Code!=200 || json.Unmarshal(got.Body.Bytes(),&payload)!=nil ||
  payload.Token!=tokens.token || tokens.calls!=1 ||
  got.Header().Get("Access-Control-Allow-Origin")!=Origin ||
  got.Header().Get("Access-Control-Allow-Credentials")!="true"{
  t.Fatalf("production token exchange broken %d",got.Code)
 }
 logout:=requestBrowser(browserLogoutPath,"POST",productionIssuer,"{}")
 logout.AddCookie(c)
 w=browserCall(h,logout)
 if w.Code!=204 || account.logouts!=1 || len(w.Result().Cookies())!=1 ||
  w.Result().Cookies()[0].MaxAge!=-1{t.Fatal("production logout did not revoke/clear cookie")}
 if w.Header().Get("Access-Control-Allow-Origin")!=""{
  t.Fatal("logout must not grant cross-origin token access")
 }
}

func TestProductionBrowserDeniesCrossEnvironmentCSRFAndBadContent(t *testing.T){
 cases:=[]struct{name,path,method,origin,body string;change func(*http.Request);want int}{
  {"http login",browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password"}`,func(r *http.Request){r.TLS=nil},403},
  {"wrong host",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Host="id-staging.shadowops.dpdns.org"},403},
  {"untrusted forwarded host",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Host="evil.test";r.Header.Set("X-Forwarded-Host",Host)},403},
  {"wrong origin",browserLoginPath,"POST",Origin,"{}",nil,403},
  {"staging origin",browserLoginPath,"POST","https://id-staging.shadowops.dpdns.org","{}",nil,403},
  {"missing origin",browserLoginPath,"POST","","{}",nil,403},
  {"multiple origins",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Header.Add("Origin",productionIssuer)},403},
  {"cross site login",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Header.Set("Sec-Fetch-Site","cross-site")},403},
  {"bad content",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Header.Set("Content-Type","text/plain")},415},
  {"double content",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Header.Add("Content-Type","application/json")},415},
  {"compressed",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.Header.Set("Content-Encoding","gzip")},415},
  {"query",browserLoginPath,"POST",productionIssuer,"{}",func(r *http.Request){r.URL.RawQuery="audience=football"},400},
  {"unknown field",browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password","audience":"football"}`,nil,400},
  {"trailing json",browserLoginPath,"POST",productionIssuer,"{} {}",nil,400},
  {"oversize",browserLoginPath,"POST",productionIssuer,strings.Repeat("a",5000),nil,400},
  {"bad username",browserLoginPath,"POST",productionIssuer,`{"username":"admin.root","password":"correct-password"}`,nil,400},
  {"GET login",browserLoginPath,"GET",productionIssuer,"",nil,405},
  {"token from staging",browserTokenPath,"POST","https://staging.bridgesquad.shadowops.dpdns.org","{}",nil,403},
  {"token same ID origin",browserTokenPath,"POST",productionIssuer,"{}",nil,403},
  {"token no cookie",browserTokenPath,"POST",Origin,"{}",nil,401},
  {"token with bearer",browserTokenPath,"POST",Origin,"{}",func(r *http.Request){r.Header.Set("Authorization","Bearer xyz")},400},
  {"token unknown field",browserTokenPath,"POST",Origin,`{"subject":"someone"}`,nil,400},
  {"logout from Bridge Squad",browserLogoutPath,"POST",Origin,"{}",nil,403},
  {"unprovisioned registration", "/api/identity/register","POST",productionIssuer,"{}",nil,503},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   h,acc,tokens,_:=setupBrowser()
   r:=requestBrowser(tc.path,tc.method,tc.origin,tc.body)
   if tc.change!=nil{tc.change(r)}
   w:=browserCall(h,r)
   if w.Code!=tc.want || acc.logins!=0 || acc.logouts!=0 || tokens.calls!=0 ||
    w.Header().Get("Set-Cookie")!=""{
    t.Fatalf("unexpected auth %d want %d, accounts %d %d tokens %d",w.Code,tc.want,acc.logins,acc.logouts,tokens.calls)
   }
  })
 }
}

func TestProductionLoginPageExactReturnAndNoStagingAssets(t *testing.T){
 h,_,_,_:=setupBrowser()
 for _,p:=range []string{"/login?app=bridgesquad",browserAssetPath}{
  w:=browserCall(h,requestBrowser(p,"GET","",""))
  if w.Code!=200 || w.Header().Get("Content-Security-Policy")=="" || w.Header().Get("Set-Cookie")!=""{
   t.Fatalf("invalid auth page %s %d",p,w.Code)
  }
  if strings.Contains(w.Body.String(),"id-staging") || strings.Contains(w.Body.String(),"staging.bridgesquad"){
   t.Fatal("login page referenced staging")
  }
  if p=="/login?app=bridgesquad"{
   html:=w.Body.String()
   if !strings.Contains(html,`data-return-url="`+prodLoginReturn+`"`) ||
    !strings.Contains(html,`class="brand" href="`+prodLoginReturn+`"`) ||
    !strings.Contains(html,`class="return-link" href="`+prodLoginReturn+`"`) ||
    !strings.Contains(html,"Bridge Squad") || !strings.Contains(w.Header().Get("Content-Security-Policy"),"form-action 'self'"){
    t.Fatal("exact Bridge Squad login destination or CSP missing")
   }
  }else if !strings.Contains(w.Body.String(),"/api/identity/login"){
   t.Fatal("login JS cannot post production credentials")
  }
 }
 for _,p:=range []string{"/login?app=football","/login?app=bridgesquad&next=https://evil.test","/login","/login?app=bridgesquad&app=bridgesquad"}{
  if w:=browserCall(h,requestBrowser(p,"GET","",""));w.Code!=400{
   t.Fatalf("unexpected product allowed %s %d",p,w.Code)
  }
 }
}
func TestProductionTokenCORSPreflightOnlyExactGame(t *testing.T){
 for _,tc:=range []struct{origin,headers,method string;cookie bool;status int}{
  {Origin,"content-type","POST",false,204},
  {productionIssuer,"content-type","POST",false,403},
  {"https://evil.test","content-type","POST",false,403},
  {Origin,"content-type,authorization","POST",false,403},
  {Origin,"content-type","GET",false,403},
  {Origin,"content-type","POST",true,403},
 }{
  h,acc,tokens,_:=setupBrowser()
  req:=requestBrowser(browserTokenPath,"OPTIONS",tc.origin,"")
  req.Header.Set("Access-Control-Request-Headers",tc.headers)
  req.Header.Set("Access-Control-Request-Method",tc.method)
  if tc.cookie{req.Header.Set("Cookie","a=b")}
  w:=browserCall(h,req)
  if w.Code!=tc.status || acc.logins!=0 || tokens.calls!=0{
   t.Fatalf("bad CORS preflight status %d want %d",w.Code,tc.status)
  }
  if tc.status==204 && (w.Header().Get("Access-Control-Allow-Origin")!=Origin ||
   w.Header().Get("Access-Control-Allow-Credentials")!="true" ||
   w.Header().Get("Access-Control-Allow-Headers")!="Content-Type"){
   t.Fatal("correct game CORS preflight missing")
  }
 }
}
func TestProductionBrowserNegativeErrorsAndRateLimit(t *testing.T){
 h,a,_,_:=setupBrowser()
 a.issueErr=ErrAccountDenied
 req:=requestBrowser(browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password"}`)
 if w:=browserCall(h,req);w.Code!=401 || w.Header().Get("Set-Cookie")!=""{t.Fatal("bad credentials leaked session")}
 a.issueErr=errors.New("Mongo unavailable")
 if w:=browserCall(h,requestBrowser(browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password"}`));w.Code!=503{
  t.Fatal("backend failure not fail-closed")
 }
 a.issueErr=nil
 for i:=0;i<6;i++{_ = browserCall(h,requestBrowser(browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"wrong"}`))}
 if w:=browserCall(h,requestBrowser(browserLoginPath,"POST",productionIssuer,`{"username":"matthias","password":"correct-password"}`));w.Code!=429{
  t.Fatal("login guessing not throttled")
 }
}


func TestProductionLogoutPageIsExplicitUserActionAndNeverGetSideEffect(t *testing.T){
 h,account,tokens,_:=setupBrowser()
 page:=browserCall(h,requestBrowser("/logout?app=bridgesquad","GET","",""))
 if page.Code!=200 || account.logouts!=0 || tokens.calls!=0 ||
  page.Header().Get("Set-Cookie")!="" {
  t.Fatalf("GET logout must render confirmation without revoking, status=%d",page.Code)
 }
 if !strings.Contains(page.Body.String(),`<form id="logout-form">`) ||
  !strings.Contains(page.Body.String(),`data-return-url="`+Origin+`/"`) ||
  !strings.Contains(page.Body.String(),`src="/assets/logout-production.js"`) ||
  !strings.Contains(page.Body.String(),"Cerrar mi sesión") ||
  !strings.Contains(page.Header().Get("Content-Security-Policy"),"form-action 'self'"){
  t.Fatal("logout confirmation page missing exact safe return, CSP or explicit submit")
 }
 script:=browserCall(h,requestBrowser(browserLogoutAssetPath,"GET","",""))
 if script.Code!=200 || account.logouts!=0 || script.Header().Get("Set-Cookie")!=""{
  t.Fatal("logout script cannot log out via GET")
 }
 js:=script.Body.String()
 for _,required:=range []string{
  "form.addEventListener('submit'", "event.preventDefault()",
  "fetch('/api/identity/logout'", "method:'POST'",
  "credentials:'same-origin'", "redirect:'error'",
  "headers:{'Content-Type':'application/json'}", "body:'{}'",
  "if(response.status!==204)", "location.replace(document.body.dataset.returnUrl)",
 } {
  if !strings.Contains(js,required){t.Fatalf("logout script missing safe gate %q",required)}
 }
 if strings.Contains(js,"window.localStorage") || strings.Contains(js,"id-staging.") {
  t.Fatal("logout must not access game saves or staging Identity")
 }
 for _,path:=range []string{
  "/logout", "/logout?app=football",
  "/logout?app=bridgesquad&next=https://evil.test",
  "/logout?app=bridgesquad&app=bridgesquad",
  "/assets/logout-production.js?foo=bar",
 } {
  if got:=browserCall(h,requestBrowser(path,"GET","",""));got.Code!=400 {
   t.Fatalf("unsafe logout URL accepted: %s status %d",path,got.Code)
  }
 }
 for _,path:=range []string{"/logout?app=bridgesquad","/assets/logout-production.js"} {
  if got:=browserCall(h,requestBrowser(path,"POST",productionIssuer,"{}"));got.Code!=405{
   t.Fatalf("POST must not treat logout page as mutating API, got %d",got.Code)
  }
 }
 if account.logouts!=0 {
  t.Fatal("GET or static asset unexpectedly revoked a session")
 }
}
