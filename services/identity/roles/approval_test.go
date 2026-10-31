package roles

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func roleChangeFixture(now time.Time) RoleChange {
	return RoleChange{
		Environment: "staging", Action: SetRoleAction,
		Subject: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		From:    User, To: Admin, ExpectedSessionVersion: 3, PolicyGeneration: 2,
		ReviewIssue:    "https://github.com/evilsysadmin/shadowops-infra/issues/287",
		EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 32),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(4 * time.Minute).Unix(),
	}
}

func TestRoleChangeRequiresTwoPinnedSignersAndExactIntent(t *testing.T) {
	opPublic, op, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	secPublic, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	v, err := NewApprovalVerifier(opPublic, secPublic)
	if err != nil { t.Fatal(err) }
	now := time.Now().UTC().Truncate(time.Second)
	c := roleChangeFixture(now)
	message, err := ApprovalMessage(c)
	if err != nil { t.Fatal(err) }
	if !bytes.HasPrefix(message, []byte(roleApprovalDomain)) {
		t.Fatal("role grant not domain-separated")
	}
	if bytes.HasPrefix(message, []byte("shadowops-identity-admin-suspension-v1")) {
		t.Fatal("role change confusable with account suspension")
	}
	approval := SignedRoleChange{Change: c, OperatorSignature: ed25519.Sign(op, message), SecuritySignature: ed25519.Sign(sec, message)}
	if err := v.Verify(approval, now); err != nil { t.Fatal(err) }
	if err := v.Verify(approval, now.Add(4*time.Minute)); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("expired authorization still valid")
	}
	if err := v.Verify(approval, now.Add(-31*time.Second)); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("premature authorization accepted")
	}
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	if _, err := NewApprovalVerifier(opPublic, opPublic); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("same signer holds both roles")
	}
	if _, err := NewApprovalVerifier(opPublic, nil); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("missing approver allowed")
	}
	otherVerifier, err := NewApprovalVerifier(opPublic, wrongKey)
	if err != nil { t.Fatal(err) }
	if err := otherVerifier.Verify(approval, now); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("wrong configured security approver authorized change")
	}
	mutate := func(change func(*SignedRoleChange)) {
		t.Helper()
		invalid := approval
		change(&invalid)
		if err := v.Verify(invalid, now); !errors.Is(err, ErrRoleApprovalDenied) {
			t.Fatal("mutated role change verified")
		}
	}
	mutate(func(a *SignedRoleChange) {
		a.OperatorSignature, a.SecuritySignature = a.SecuritySignature, a.OperatorSignature
	})
	mutate(func(a *SignedRoleChange) { a.Change.To = User })
	mutate(func(a *SignedRoleChange) { a.Change.To = "superadmin" })
	mutate(func(a *SignedRoleChange) { a.Change.Subject = "22222222-2222-4222-8222-222222222222" })
	mutate(func(a *SignedRoleChange) { a.Change.Environment = "production" })
	mutate(func(a *SignedRoleChange) { a.Change.ExpectedSessionVersion++ })
	mutate(func(a *SignedRoleChange) { a.Change.PolicyGeneration++ })
	mutate(func(a *SignedRoleChange) { a.Change.ReviewIssue = "https://example.com/287" })
	mutate(func(a *SignedRoleChange) { a.Change.Nonce = strings.Repeat("c", 32) })
	mutate(func(a *SignedRoleChange) { a.Change.IssuedAt++ })
	mutate(func(a *SignedRoleChange) { a.Change.ExpiresAt++ })
	mutate(func(a *SignedRoleChange) { a.OperatorSignature = nil })
	mutate(func(a *SignedRoleChange) { a.SecuritySignature = nil })
	// Neither a login nor an unsigned request gets this verifier's keys.
	var noVerifier *ApprovalVerifier
	if err := noVerifier.Verify(approval, now); !errors.Is(err, ErrRoleApprovalDenied) {
		t.Fatal("unconfigured verifier authorized role change")
	}
}

func TestRoleChangeRejectsAmbiguousOrUnreviewedRequests(t *testing.T) {
	c := roleChangeFixture(time.Now())
	cases := []struct {
		name   string
		mutate func(*RoleChange)
	}{
		{"wrong action", func(a *RoleChange) { a.Action = "grant-admin" }},
		{"wrong environment", func(a *RoleChange) { a.Environment = "production" }},
		{"missing review", func(a *RoleChange) { a.ReviewIssue = "" }},
		{"display name", func(a *RoleChange) { a.Subject = "evilsysadmin" }},
		{"uppercase subject", func(a *RoleChange) { a.Subject = strings.ToUpper(a.Subject) }},
		{"no-op", func(a *RoleChange) { a.To = a.From }},
		{"unknown role", func(a *RoleChange) { a.To = "root" }},
		{"role wildcard", func(a *RoleChange) { a.From = "*" }},
		{"missing role", func(a *RoleChange) { a.From = "" }},
		{"missing session fence", func(a *RoleChange) { a.ExpectedSessionVersion = 0 }},
		{"overflow session fence", func(a *RoleChange) { a.ExpectedSessionVersion = 9223372036854775807 }},
		{"missing generation", func(a *RoleChange) { a.PolicyGeneration = 0 }},
		{"overflow generation", func(a *RoleChange) { a.PolicyGeneration = 9223372036854775807 }},
		{"bad evidence", func(a *RoleChange) { a.EvidenceSHA256 = "SHA256" }},
		{"bad nonce", func(a *RoleChange) { a.Nonce = "" }},
		{"missing issue", func(a *RoleChange) { a.ReviewIssue = "https://github.com/other/repo/issues/287" }},
		{"long life", func(a *RoleChange) { a.ExpiresAt = a.IssuedAt + 301 }},
		{"negative life", func(a *RoleChange) { a.ExpiresAt = a.IssuedAt - 1 }},
		{"out of bounds epoch", func(a *RoleChange) { a.IssuedAt = 1 }},
		{"future expiration", func(a *RoleChange) { a.ExpiresAt = 4102444801 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := c
			tc.mutate(&bad)
			if _, err := ApprovalMessage(bad); !errors.Is(err, ErrRoleApprovalDenied) {
				t.Fatalf("invalid request accepted: %v", err)
			}
		})
	}
	c.From = Admin
	c.To = User // Revocation is valid and must be explicitly signed.
	if _, err := ApprovalMessage(c); err != nil {
		t.Fatal("role downgrade blocked", err)
	}
}
