package revocation

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

func approvalTestKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func validTestSuspension(now time.Time) SuspensionApproval {
	return SuspensionApproval{
		Environment: "staging",
		Action: SuspendAndRevokeAction,
		Subject: "11111111-1111-4111-8111-111111111111",
		ExpectedSessionVersion: 7,
		ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287",
		EvidenceSHA256: strings.Repeat("a", 64),
		Nonce: strings.Repeat("b", 32),
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
	}
}

func signedTestSuspension(t *testing.T, a SuspensionApproval, op, sec ed25519.PrivateKey) SignedSuspension {
	t.Helper()
	msg, err := ApprovalMessage(a)
	if err != nil {
		t.Fatal(err)
	}
	return SignedSuspension{
		Approval: a,
		OperatorSignature: ed25519.Sign(op, msg),
		SecuritySignature: ed25519.Sign(sec, msg),
	}
}

func TestApprovalRequiresTwoDistinctPinnedRoles(t *testing.T) {
	op, sec := approvalTestKeys()
	v, err := NewApprovalVerifier(op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0).UTC()
	signed := signedTestSuspension(t, validTestSuspension(now), op, sec)
	if err := v.Verify(signed, now); err != nil {
		t.Fatal("valid independent dual signature rejected", err)
	}
	// Both signers approve the same message but cannot swap their roles.
	swapped := signed
	swapped.OperatorSignature, swapped.SecuritySignature = signed.SecuritySignature, signed.OperatorSignature
	if !errors.Is(v.Verify(swapped, now), ErrApprovalDenied) {
		t.Fatal("swapped operator/security signatures accepted")
	}
	missing := signed
	missing.SecuritySignature = nil
	if !errors.Is(v.Verify(missing, now), ErrApprovalDenied) {
		t.Fatal("single signature was accepted")
	}
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	third := signed
	msg, _ := ApprovalMessage(third.Approval)
	third.SecuritySignature = ed25519.Sign(foreign, msg)
	if !errors.Is(v.Verify(third, now), ErrApprovalDenied) {
		t.Fatal("untrusted security key accepted")
	}
	if _, err := NewApprovalVerifier(op.Public().(ed25519.PublicKey), op.Public().(ed25519.PublicKey)); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("same public key could approve twice", err)
	}
	if _, err := NewApprovalVerifier(nil, sec.Public().(ed25519.PublicKey)); !errors.Is(err, ErrApprovalDenied) {
		t.Fatal("missing authority accepted", err)
	}
	if !errors.Is((*ApprovalVerifier)(nil).Verify(signed, now), ErrApprovalDenied) {
		t.Fatal("nil verifier accepted")
	}
	if !errors.Is(v.Verify(signed, time.Time{}), ErrApprovalDenied) {
		t.Fatal("unset clock accepted")
	}
}

func TestApprovalBindsAllSecurityCriticalClaims(t *testing.T) {
	op, sec := approvalTestKeys()
	v, err := NewApprovalVerifier(op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0).UTC()
	signed := signedTestSuspension(t, validTestSuspension(now), op, sec)
	mutations := map[string]func(*SuspensionApproval){
		"environment": func(a *SuspensionApproval) { a.Environment = "production" },
		"action": func(a *SuspensionApproval) { a.Action = "activate-account" },
		"subject": func(a *SuspensionApproval) { a.Subject = "22222222-2222-4222-8222-222222222222" },
		"version": func(a *SuspensionApproval) { a.ExpectedSessionVersion++ },
		"review ticket": func(a *SuspensionApproval) { a.ReviewIssue = "https://github.com/evilsysadmin/shadowops-infra/issues/288" },
		"evidence digest": func(a *SuspensionApproval) { a.EvidenceSHA256 = strings.Repeat("c", 64) },
		"nonce": func(a *SuspensionApproval) { a.Nonce = strings.Repeat("d", 32) },
		"issued at": func(a *SuspensionApproval) { a.IssuedAt-- },
		"expires at": func(a *SuspensionApproval) { a.ExpiresAt-- },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := signed
			mutate(&tampered.Approval)
			if !errors.Is(v.Verify(tampered, now), ErrApprovalDenied) {
				t.Fatal("approved claims could be altered")
			}
		})
	}
	copyOp := append(ed25519.PublicKey(nil), op.Public().(ed25519.PublicKey)...)
	copySec := append(ed25519.PublicKey(nil), sec.Public().(ed25519.PublicKey)...)
	owned, err := NewApprovalVerifier(copyOp, copySec)
	if err != nil {
		t.Fatal(err)
	}
	copyOp[0] ^= 1
	copySec[0] ^= 1
	if err := owned.Verify(signed, now); err != nil {
		t.Fatal("authority allowed mutation of its pinned key copies", err)
	}
}

func TestApprovalRejectsInvalidClaimsEvenIfResigned(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	cases := map[string]func(*SuspensionApproval){
		"production": func(a *SuspensionApproval) { a.Environment = "production" },
		"empty environment": func(a *SuspensionApproval) { a.Environment = "" },
		"unlisted action": func(a *SuspensionApproval) { a.Action = "issue-session" },
		"wrong subject": func(a *SuspensionApproval) { a.Subject = "legacy-user" },
		"uppercase uuid": func(a *SuspensionApproval) { a.Subject = strings.ToUpper(a.Subject) },
		"zero version": func(a *SuspensionApproval) { a.ExpectedSessionVersion = 0 },
		"negative version": func(a *SuspensionApproval) { a.ExpectedSessionVersion = -1 },
		"overflow version": func(a *SuspensionApproval) { a.ExpectedSessionVersion = int64(^uint64(0) >> 1) },
		"foreign ticket": func(a *SuspensionApproval) { a.ReviewIssue = "https://github.com/foreign/repo/issues/287" },
		"unbounded ticket": func(a *SuspensionApproval) { a.ReviewIssue += "?token=secret" },
		"malformed ticket": func(a *SuspensionApproval) { a.ReviewIssue = "http://github.com/evilsysadmin/shadowops-infra/issues/287" },
		"empty evidence": func(a *SuspensionApproval) { a.EvidenceSHA256 = "" },
		"uppercase evidence": func(a *SuspensionApproval) { a.EvidenceSHA256 = strings.ToUpper(a.EvidenceSHA256) },
		"bad nonce": func(a *SuspensionApproval) { a.Nonce = "deadbeef" },
		"zero time": func(a *SuspensionApproval) { a.IssuedAt = 0 },
		"negative validity": func(a *SuspensionApproval) { a.ExpiresAt = a.IssuedAt - 1 },
		"zero validity": func(a *SuspensionApproval) { a.ExpiresAt = a.IssuedAt },
		"too long": func(a *SuspensionApproval) { a.ExpiresAt++ },
		"far future": func(a *SuspensionApproval) { a.ExpiresAt = 4102444801 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := validTestSuspension(now)
			mutate(&a)
			if _, err := ApprovalMessage(a); !errors.Is(err, ErrApprovalDenied) {
				t.Fatal("invalid command can be signed")
			}
		})
	}
}

func TestApprovalClockWindowAndCanonicalMessage(t *testing.T) {
	op, sec := approvalTestKeys()
	v, err := NewApprovalVerifier(op.Public().(ed25519.PublicKey), sec.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0).UTC()
	a := validTestSuspension(now)
	msg, err := ApprovalMessage(a)
	if err != nil || !bytes.HasPrefix(msg, []byte(approvalDomain)) {
		t.Fatal("domain-separated canonical payload missing", err)
	}
	again, err := ApprovalMessage(a)
	if err != nil || !bytes.Equal(msg, again) {
		t.Fatal("signing bytes are not deterministic", err)
	}
	signed := signedTestSuspension(t, a, op, sec)
	for _, test := range []struct {
		name string
		when time.Time
		allowed bool
	}{
		{"within early skew", now.Add(-30*time.Second), true},
		{"too early", now.Add(-31*time.Second), false},
		{"valid", now.Add(2*time.Minute), true},
		{"at expiration", now.Add(5*time.Minute), false},
		{"after expiration", now.Add(6*time.Minute), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := v.Verify(signed, test.when)
			if test.allowed && err != nil {
				t.Fatal("valid approval rejected", err)
			}
			if !test.allowed && !errors.Is(err, ErrApprovalDenied) {
				t.Fatal("expired or future approval accepted", err)
			}
		})
	}
}
