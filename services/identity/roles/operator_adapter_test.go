package roles

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"strings"
	"testing"
	"time"
)

func TestOperatorRequestRejectsAmbiguousOrExcessiveInput(t *testing.T) {
	cases := []string{`{"change":{},"change":{}}`, `{"change":{},"Change":{}}`, `{"change":{"environment":"staging","environment":"production"}}`, `{"change":{},"unexpected":true}`, `{"change":{}} {}`, `{"change":{},`, strings.Repeat(" ", maxOperatorRequestBytes+1)}
	for _, input := range cases {
		var request changeRequest
		if err := decodeOperatorRequest(strings.NewReader(input), &request); !errors.Is(err, ErrOperatorRequest) {
			t.Fatalf("unexpected acceptance or error: %v", err)
		}
	}
}
func requestBytes(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}
func TestOperatorAdapterBootstrapAndRoleChange(t *testing.T) {
	client, db := roleReplica(t)
	ctx := context.Background()
	if err := PrepareStagingRoleJournalIndex(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCollection(ctx, rolePolicy); err != nil {
		t.Fatal(err)
	}
	authorityA, authorityB := roleBootstrapAuthorities()
	op, sec := roleKeys()
	signed := signRoleBootstrap(t, roleBootstrapStatement(time.Now().UTC(), op, sec), authorityA, authorityB, op, sec)
	bootstrap := bootstrapRequest{signed.Statement, signed.AuthorityASignature, signed.AuthorityBSignature, signed.OperatorProof, signed.SecurityProof}
	pubA := authorityA.Public().(ed25519.PublicKey)
	pubB := authorityB.Public().(ed25519.PublicKey)
	bad := bootstrap
	bad.SecurityProof = bytes.Repeat([]byte{42}, ed25519.SignatureSize)
	if err := ApplyBootstrapRequest(ctx, client, pubA, pubB, requestBytes(t, bad)); err == nil {
		t.Fatal("accepted invalid bootstrap proof")
	}
	if count, err := db.Collection(rolePolicy).CountDocuments(ctx, bson.D{}); err != nil || count != 0 {
		t.Fatalf("invalid bootstrap mutated policy: %d %v", count, err)
	}
	if err := ApplyBootstrapRequest(ctx, client, pubA, pubB, requestBytes(t, bootstrap)); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := ApplyBootstrapRequest(ctx, client, pubA, pubB, requestBytes(t, bootstrap)); err == nil {
		t.Fatal("accepted bootstrap replay")
	}
	const subject = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	roleAccount(t, db, subject, 7, User)
	now := time.Now().UTC()
	change := RoleChange{Environment: "staging", Action: SetRoleAction, Subject: subject, From: User, To: Admin, ExpectedSessionVersion: 7, PolicyGeneration: 1, ReviewIssue: "https://github.com/evilsysadmin/shadowops-infra/issues/287", EvidenceSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("c", 32), IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	approved := signRoleChange(t, op, sec, change)
	request := changeRequest{approved.Change, approved.OperatorSignature, approved.SecuritySignature}
	opPub := op.Public().(ed25519.PublicKey)
	secPub := sec.Public().(ed25519.PublicKey)
	expiredChange := change
	expiredChange.IssuedAt = now.Add(-2 * time.Minute).Unix()
	expiredChange.ExpiresAt = now.Add(-time.Minute).Unix()
	expiredSigned := signRoleChange(t, op, sec, expiredChange)
	expired := changeRequest{expiredSigned.Change, expiredSigned.OperatorSignature, expiredSigned.SecuritySignature}
	if err := ApplyRoleChangeRequest(ctx, client, opPub, secPub, requestBytes(t, expired)); err == nil {
		t.Fatal("accepted expired role request")
	}
	badChange := request
	badChange.SecuritySignature = bytes.Repeat([]byte{43}, ed25519.SignatureSize)
	if err := ApplyRoleChangeRequest(ctx, client, opPub, secPub, requestBytes(t, badChange)); err == nil {
		t.Fatal("accepted invalid role signature")
	}
	if role, version := roleState(t, db, subject); role != "user" || version != 7 {
		t.Fatalf("invalid request changed account: %s %d", role, version)
	}
	if err := ApplyRoleChangeRequest(ctx, client, opPub, secPub, requestBytes(t, request)); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if role, version := roleState(t, db, subject); role != "admin" || version != 8 {
		t.Fatalf("unexpected account: %s %d", role, version)
	}
	if err := ApplyRoleChangeRequest(ctx, client, opPub, secPub, requestBytes(t, request)); err == nil {
		t.Fatal("accepted role replay")
	}
}
