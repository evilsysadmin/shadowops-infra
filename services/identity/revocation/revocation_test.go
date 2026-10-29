package revocation

import (
	"context"
	"errors"
	"math"
	"testing"
)

const syntheticSubject = "11111111-1111-4111-8111-111111111111"

func TestOfflineInputsFailClosed(t *testing.T) {
	if _, err := NewStagingRevoker(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing Mongo client accepted")
	}
	var missing *Revoker
	if err := missing.SuspendAndRevoke(context.Background(), syntheticSubject, 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil revoker accepted")
	}
	for _, version := range []int64{-1, 0, math.MaxInt64} {
		if err := missing.SuspendAndRevoke(context.Background(), syntheticSubject, version); !errors.Is(err, ErrInvalid) {
			t.Fatal("unexpected behavior for invalid version", version)
		}
	}
	if subjectPattern.MatchString("legacy-username") || !subjectPattern.MatchString(syntheticSubject) {
		t.Fatal("invalid UUIDv4 validation")
	}
}
