package mongostore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/session"
)

func TestFailClosedWithoutDatabase(t *testing.T) {
	if _, err := New(context.Background(), nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil DB accepted")
	}
	var s *Store
	if err := s.Create(context.Background(), session.Record{}); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil store create")
	}
	if _, _, err := s.Get(context.Background(), "staging", [32]byte{1}); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil store read")
	}
	if _, err := s.Swap(context.Background(), "staging", [32]byte{1}, session.Record{}, time.Now()); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil store swap")
	}
	if err := s.Delete(context.Background(), "staging", [32]byte{1}); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil store revoke")
	}
	if err := s.DeleteSubject(context.Background(), "staging", "subject"); !errors.Is(err, ErrInvalidStore) {
		t.Fatal("nil store subject revoke")
	}
}
