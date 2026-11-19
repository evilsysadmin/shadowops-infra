package production

import (
 "context"
 "errors"
 "testing"
 "time"

 "github.com/evilsysadmin/shadowops-infra/services/identity/session"
)

func TestProductionStoreRejectsEmptyAndLegacySessions(t *testing.T) {
 ctx:=context.Background()
 if _,err:=NewSessionStore(ctx,nil);!errors.Is(err,ErrInvalidStore){t.Fatal("nil database accepted")}
 if _,err:=OpenExistingSessionStore(nil);!errors.Is(err,ErrInvalidStore){t.Fatal("nil existing database accepted")}
 if _,err:=NewSessionStore(nil,nil);!errors.Is(err,ErrInvalidStore){t.Fatal("nil context accepted")}
 var missing *Store
 rec:=session.Record{Digest:[32]byte{1},Environment:"production",Subject:"11111111-1111-4111-8111-111111111111",IssuedAt:time.Now().UTC(),ExpiresAt:time.Now().UTC().Add(time.Hour),SessionVersion:3}
 if err:=missing.Create(ctx,rec);!errors.Is(err,ErrInvalidStore){t.Fatal("nil store accepted create")}
 if _,_,err:=missing.Get(ctx,"production",rec.Digest);!errors.Is(err,ErrInvalidStore){t.Fatal("nil store accepted get")}
 if _,err:=missing.Swap(ctx,"production",rec.Digest,rec,time.Now());!errors.Is(err,ErrInvalidStore){t.Fatal("nil store accepted CAS")}
 if err:=missing.Delete(ctx,"production",rec.Digest);!errors.Is(err,ErrInvalidStore){t.Fatal("nil store accepted delete")}
 if err:=missing.DeleteSubject(ctx,"production",rec.Subject);!errors.Is(err,ErrInvalidStore){t.Fatal("nil store accepted revoke")}
 if !validProductionRecord(rec){t.Fatal("valid versioned session rejected")}
 for name,change:=range map[string]func(*session.Record){
  "staging":func(r *session.Record){r.Environment="staging"},
  "unversioned":func(r *session.Record){r.SessionVersion=0},
  "negative version":func(r *session.Record){r.SessionVersion=-1},
  "non UUID":func(r *session.Record){r.Subject="bridge-user"},
  "no digest":func(r *session.Record){r.Digest=[32]byte{}},
  "expired times":func(r *session.Record){r.ExpiresAt=r.IssuedAt},
  "too long":func(r *session.Record){r.ExpiresAt=r.IssuedAt.Add(25*time.Hour)},
 } {
  t.Run(name,func(t *testing.T){
   candidate:=rec;change(&candidate)
   if validProductionRecord(candidate){t.Fatal("unsafe production session admitted")}
  })
 }
}
