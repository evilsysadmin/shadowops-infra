package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic test-only store. Production requires a durable and atomic DB driver.
type memoryTestStore struct {
	mu sync.Mutex
	items map[[32]byte]Record
	fail bool
}
func newTestStore() *memoryTestStore { return &memoryTestStore{items: make(map[[32]byte]Record)} }
func (s *memoryTestStore) Create(_ context.Context, r Record) error {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.fail { return errors.New("synthetic error") }
	if _, ok := s.items[r.Digest]; ok { return errors.New("collision") }
	s.items[r.Digest] = r
	return nil
}
func (s *memoryTestStore) Get(_ context.Context, env string, digest [32]byte) (Record, bool, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.fail { return Record{}, false, errors.New("synthetic error") }
	r, ok := s.items[digest]
	if ok && r.Environment != env { return Record{}, false, nil }
	return r, ok, nil
}
func (s *memoryTestStore) Swap(_ context.Context, env string, old [32]byte, next Record, now time.Time) (bool, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.fail { return false, errors.New("synthetic error") }
	r, ok := s.items[old]
	if !ok || r.Environment != env || r.Subject != next.Subject || !now.Before(r.ExpiresAt) || !r.ExpiresAt.Equal(next.ExpiresAt) || next.Environment != env { return false, nil }
	if _, collision := s.items[next.Digest]; collision { return false, nil }
	delete(s.items, old); s.items[next.Digest] = next
	return true, nil
}
func (s *memoryTestStore) Delete(_ context.Context, env string, digest [32]byte) error {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.fail { return errors.New("synthetic error") }
	if r, ok := s.items[digest]; ok && r.Environment == env { delete(s.items, digest) }
	return nil
}
func (s *memoryTestStore) DeleteSubject(_ context.Context, env, subject string) error {
	s.mu.Lock(); defer s.mu.Unlock()
	if s.fail { return errors.New("synthetic error") }
	for k, r := range s.items { if r.Environment == env && r.Subject == subject { delete(s.items, k) } }
	return nil
}

const (
	alice = "11111111-1111-4111-8111-111111111111"
	bob = "22222222-2222-4222-8222-222222222222"
)
func manager(t *testing.T, env string, store Store, now *time.Time) *Manager {
	t.Helper()
	m, err := NewManager(env, store)
	if err != nil { t.Fatal(err) }
	m.clock = func() time.Time { return *now }
	return m
}
func TestIssueValidateAndAbsoluteExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	store := newTestStore()
	m := manager(t, "staging", store, &now)
	h, err := m.Issue(ctx, alice)
	if err != nil || len(h) != 47 || !strings.HasPrefix(h,"so1_") { t.Fatal("invalid opaque handle",err) }
	if sub,err:=m.Validate(ctx,h); err!=nil || sub!=alice { t.Fatal("failed to validate",err) }
	store.mu.Lock()
	for digest,rec:=range store.items {
		if rec.Digest!=digest || rec.Environment!="staging" || rec.Subject!=alice || rec.ExpiresAt.Sub(rec.IssuedAt)!=Lifetime { t.Error("stored unsafe metadata") }
		if strings.Contains(string(digest[:]),h) { t.Error("raw handle retained") }
	}
	store.mu.Unlock()
	now=now.Add(Lifetime)
	if _,err:=m.Validate(ctx,h); !errors.Is(err,ErrDenied) { t.Fatal("expired session accepted") }
}
func TestRotateIsSingleUseAndCannotExtendExpiry(t *testing.T) {
	ctx:=context.Background(); now:=time.Unix(1800000000,0)
	m:=manager(t,"staging",newTestStore(),&now)
	h,err:=m.Issue(ctx,alice); if err!=nil { t.Fatal(err) }
	now=now.Add(time.Hour)
	next,err:=m.Rotate(ctx,h); if err!=nil { t.Fatal(err) }
	if _,err:=m.Validate(ctx,h); !errors.Is(err,ErrDenied) { t.Fatal("old handle valid") }
	if _,err:=m.Rotate(ctx,h); !errors.Is(err,ErrDenied) { t.Fatal("replayed refresh accepted") }
	if sub,err:=m.Validate(ctx,next); err!=nil || sub!=alice { t.Fatal("rotated handle invalid") }
	now=now.Add(Lifetime-time.Hour)
	if _,err:=m.Validate(ctx,next); !errors.Is(err,ErrDenied) { t.Fatal("refresh extended expiry") }
}
func TestConcurrentRefreshHasExactlyOneWinner(t *testing.T) {
	ctx:=context.Background(); now:=time.Unix(1800000000,0)
	m:=manager(t,"staging",newTestStore(),&now)
	h,err:=m.Issue(ctx,alice); if err!=nil { t.Fatal(err) }
	var wins atomic.Int32
	var wg sync.WaitGroup
	start:=make(chan struct{})
	for i:=0;i<32;i++ {
		wg.Add(1)
		go func() {
			defer wg.Done(); <-start
			next,err:=m.Rotate(ctx,h)
			if err==nil { if next==h { t.Error("reused old handle") }; wins.Add(1) } else if !errors.Is(err,ErrDenied) { t.Error("unexpected refresh error",err) }
		}()
	}
	close(start); wg.Wait()
	if wins.Load()!=1 { t.Fatalf("refresh produced %d winners",wins.Load()) }
}
func TestAccountRevocationAndEnvironmentIsolation(t *testing.T) {
	ctx:=context.Background(); now:=time.Unix(1800000000,0)
	store:=newTestStore()
	s:=manager(t,"staging",store,&now); p:=manager(t,"production",store,&now)
	a,_:=s.Issue(ctx,alice); b,_:=s.Issue(ctx,alice); c,_:=s.Issue(ctx,bob); prod,_:=p.Issue(ctx,alice)
	if _,err:=p.Validate(ctx,a); !errors.Is(err,ErrDenied) { t.Fatal("cross-environment token accepted") }
	if err:=s.RevokeSubject(ctx,alice); err!=nil { t.Fatal(err) }
	for _,h:=range []string{a,b} { if _,err:=s.Validate(ctx,h); !errors.Is(err,ErrDenied) { t.Fatal("revoked account still active") } }
	if _,err:=s.Validate(ctx,c); err!=nil { t.Fatal("other account was revoked") }
	if _,err:=p.Validate(ctx,prod); err!=nil { t.Fatal("staging revoked production account") }
	if err:=s.Revoke(ctx,c); err!=nil { t.Fatal(err) }
	if _,err:=s.Validate(ctx,c); !errors.Is(err,ErrDenied) { t.Fatal("revoke failed") }
	if err:=s.Revoke(ctx,c); err!=nil { t.Fatal("idempotent logout failed") }
}
func TestInvalidSubjectsHandlesAndCanceledContextRejected(t *testing.T) {
	ctx:=context.Background(); now:=time.Unix(1800000000,0)
	store:=newTestStore()
	for _,env:=range []string{"", "stage", "development", "PRODUCTION"} {
		if _,err:=NewManager(env,store); !errors.Is(err,ErrDenied) { t.Fatal("wrong environment accepted",env) }
	}
	if _,err:=NewManager("staging",nil); !errors.Is(err,ErrDenied) { t.Fatal("missing store accepted") }
	m:=manager(t,"staging",store,&now)
	for _,sub:=range []string{"", "alice", "11111111-1111-1111-8111-111111111111", "11111111-1111-4111-0111-111111111111", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		if _,err:=m.Issue(ctx,sub); !errors.Is(err,ErrDenied) { t.Fatal("invalid UUIDv4 accepted") }
	}
	for _,handle:=range []string{"", "so1_", "so1_!!!!", strings.Repeat("x",200), "so1_"+strings.Repeat("A",43)} {
		if _,err:=m.Validate(ctx,handle); !errors.Is(err,ErrDenied) { t.Fatal("malformed handle accepted") }
		if _,err:=m.Rotate(ctx,handle); !errors.Is(err,ErrDenied) { t.Fatal("malformed handle rotated") }
	}
	cancel,stop:=context.WithCancel(ctx); stop()
	if _,err:=m.Issue(cancel,alice); !errors.Is(err,ErrDenied) { t.Fatal("issued after cancellation") }
	if err:=m.RevokeSubject(cancel,alice); !errors.Is(err,ErrDenied) { t.Fatal("revoked after cancellation") }
}
func TestStoreFailuresAreFailClosed(t *testing.T) {
	ctx:=context.Background(); now:=time.Unix(1800000000,0)
	store:=newTestStore(); m:=manager(t,"staging",store,&now)
	store.fail=true
	if h,err:=m.Issue(ctx,alice); h!="" || !errors.Is(err,ErrStore) { t.Fatal("fail-open issuance") }
	store.fail=false
	h,_:=m.Issue(ctx,alice)
	store.fail=true
	if sub,err:=m.Validate(ctx,h); sub!="" || !errors.Is(err,ErrStore) { t.Fatal("fail-open validation") }
	if out,err:=m.Rotate(ctx,h); out!="" || !errors.Is(err,ErrStore) { t.Fatal("fail-open rotation") }
	if err:=m.Revoke(ctx,h); !errors.Is(err,ErrStore) { t.Fatal("store errors hidden on logout") }
	if err:=m.RevokeSubject(ctx,alice); !errors.Is(err,ErrStore) { t.Fatal("store errors hidden on account revoke") }
}
