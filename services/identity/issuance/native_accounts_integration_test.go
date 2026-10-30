package issuance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestNativeEnrollmentNeverClaimsLegacyNameAndRecoveryRevokesAllApps(t *testing.T) {
	client, db := replica(t)
	syntheticActive(t, db)
	ctx := context.Background()
	_, err := db.Collection("pending_accounts").UpdateOne(ctx, bson.M{"_id": alice}, bson.M{"$set": bson.M{"source": "chess-studio", "alias_key": "player"}})
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewStagingNativeAccounts(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Register(ctx, "unicode_short", "😀😀😀😀"); !errors.Is(err, ErrDenied) {
		t.Fatal("short Unicode password was counted as bytes", err)
	}
	if _, err := n.Login(ctx, "player", secret); !errors.Is(err, ErrDenied) {
		t.Fatal("native login claimed a legacy account")
	}
	code, err := n.Register(ctx, "Player", secret)
	if err != nil || len(code) != 48 {
		t.Fatal("native registration failed", err)
	}
	if _, err := n.Register(ctx, "PLAYER", secret); !errors.Is(err, ErrNameUnavailable) {
		t.Fatal("case-only duplicate native account accepted", err)
	}
	handle, err := n.Login(ctx, " player ", secret)
	if err != nil {
		t.Fatal(err)
	}
	second, err := n.Login(ctx, "player", secret)
	if err != nil || second == handle {
		t.Fatal("second browser login failed", err)
	}
	var before []appTokenClaims
	for _, app := range sharedApplications {
		signer, _ := NewStagingAppSigner(i, []byte(strings.Repeat("s", 32)), app)
		jwks, _ := signer.JWKS()
		for _, browser := range []string{handle, second} {
			token, err := signer.IssueToken(ctx, browser)
			if err != nil {
				t.Fatal(err)
			}
			c := testClaims(t, token, jwks)
			if c.Sub == alice || !uuidV4.MatchString(c.Sub) {
				t.Fatal("central signup reused legacy identity")
			}
			before = append(before, c)
		}
	}
	newPassword := "changed-central-password-2026"
	next, err := n.Recover(ctx, "player", code, newPassword)
	if err != nil || next == code || len(next) != 48 {
		t.Fatal("recovery did not rotate the backup secret", err)
	}
	for _, c := range before {
		checker, _ := NewStagingAppFreshness(i, Application(c.Aud))
		if _, err := checker.Check(ctx, c.Sub, c.Sv, c.Jti); !errors.Is(err, ErrDenied) {
			t.Fatal("recovery left a browser/application token active", c.Aud, err)
		}
	}
	if _, err := n.Login(ctx, "player", secret); !errors.Is(err, ErrDenied) {
		t.Fatal("old password survived recovery", err)
	}
	if _, err := n.Login(ctx, "player", newPassword); err != nil {
		t.Fatal("recovered account cannot log in", err)
	}
	if _, err := n.Recover(ctx, "player", code, secret); !errors.Is(err, ErrDenied) {
		t.Fatal("backup code replay accepted", err)
	}
	if _, err := i.Issue(ctx, alice, secret); err != nil {
		t.Fatal("native recovery changed the same-name legacy account", err)
	}
	var stored bson.M
	if err := db.Collection("pending_accounts").FindOne(ctx, bson.M{"source": nativeSource}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored["credential_hash"].(string), newPassword) || stored["recovery_digest"] == code || stored["recovery_digest"] == next || len(stored["recovery_digest"].(string)) != 64 || stored["credential_version"] != int64(2) || stored["session_version"] != int64(2) {
		t.Fatal("raw secrets stored or credential versions unchanged")
	}
}

func TestNativeRecoveryRollbackAndConcurrentSingleUse(t *testing.T) {
	client, db := replica(t)
	ctx := context.Background()
	i, err := NewStagingIssuer(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	n, err := NewStagingNativeAccounts(ctx, i)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	codes := make(chan string, 2)
	for range 2 {
		group.Go(func() { code, err := n.Register(ctx, "concurrent", secret); results <- err; codes <- code })
	}
	group.Wait()
	var code string
	success := 0
	for range 2 {
		if err := <-results; err == nil {
			success++
		} else if !errors.Is(err, ErrNameUnavailable) {
			t.Fatal(err)
		}
		if c := <-codes; c != "" {
			code = c
		}
	}
	if success != 1 || code == "" {
		t.Fatal("concurrent registration did not have one winner")
	}
	if _, err := n.Login(ctx, "concurrent", secret); err != nil {
		t.Fatal(err)
	}
	i.afterFence = func() error { return errors.New("synthetic recovery rollback") }
	if recovered, err := n.Recover(ctx, "concurrent", code, "replacement-password-2026"); recovered != "" || !errors.Is(err, ErrStore) {
		t.Fatal("failed transaction returned a recovery secret", err)
	}
	if count, err := db.Collection("sessions").CountDocuments(ctx, bson.D{}); err != nil || count != 1 {
		t.Fatal("rollback deleted the browser session", err)
	}
	i.afterFence = nil
	if _, err := n.Login(ctx, "concurrent", secret); err != nil {
		t.Fatal("rollback changed the password", err)
	}
	for range 2 {
		group.Go(func() { _, err := n.Recover(ctx, "concurrent", code, "replacement-password-2026"); results <- err })
	}
	group.Wait()
	success = 0
	for range 2 {
		if err := <-results; err == nil {
			success++
		} else if !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("concurrent recovery code reuse did not have exactly one winner")
	}
}
