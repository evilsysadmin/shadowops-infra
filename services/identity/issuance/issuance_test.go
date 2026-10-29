package issuance

import (
	"context"
	"errors"
	"testing"
)

func TestOfflineIssuanceRejectsInvalidInput(t *testing.T) {
	if _, err := NewStagingIssuer(context.Background(), nil); !errors.Is(err, ErrDenied) {
		t.Fatal("nil Mongo client accepted")
	}
	var issuer *Issuer
	for _, subject := range []string{"", "legacy-username", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		if handle, err := issuer.Issue(context.Background(), subject, "irrelevant"); handle != "" || !errors.Is(err, ErrDenied) {
			t.Fatal("nil issuer issued a session")
		}
	}
	if uuidV4.MatchString("chess-user") || !uuidV4.MatchString("11111111-1111-4111-8111-111111111111") {
		t.Fatal("invalid UUIDv4 contract")
	}
}
