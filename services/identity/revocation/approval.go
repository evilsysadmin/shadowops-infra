package revocation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

// The approval protocol is a pure, offline verifier. It is deliberately NOT
// wired to SuspendAndRevoke: a transactional nonce/audit journal and actual
// independent operator enrollment are required before an authorized mutation.
const (
	SuspendAndRevokeAction = "suspend-and-revoke"
	approvalDomain         = "shadowops-identity-admin-suspension-v1\n"
	approvalLifetime       = 5 * time.Minute
	approvalClockSkew      = 30 * time.Second
)

var (
	ErrApprovalDenied = errors.New("staging identity administrative approval denied")
	approvalIssue     = regexp.MustCompile(`^https://github\.com/evilsysadmin/shadowops-infra/issues/[1-9][0-9]{0,8}$`)
	approvalSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	approvalNonce     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// SuspensionApproval describes ONE specifically scoped staging suspension.
// Neither a ShadowOps login nor a GitHub issue is evidence of admin authority;
// separate, pinned, independently controlled signing keys must be enrolled
// by a trusted offline operator after reviewing evidence outside this repo.
type SuspensionApproval struct {
	Environment            string `json:"environment"`
	Action                 string `json:"action"`
	Subject                string `json:"subject"`
	ExpectedSessionVersion int64  `json:"expected_session_version"`
	ReviewIssue            string `json:"review_issue"`
	EvidenceSHA256         string `json:"evidence_sha256"`
	Nonce                  string `json:"nonce"`
	IssuedAt               int64  `json:"issued_at"`
	ExpiresAt              int64  `json:"expires_at"`
}

// SignedSuspension has explicitly ordered roles, preventing substitution of
// an operator's signature for the independent security approver.
type SignedSuspension struct {
	Approval          SuspensionApproval
	OperatorSignature []byte
	SecuritySignature []byte
}

// ApprovalVerifier owns copies of two separately provisioned, pinned public
// keys. Public keys sourced from incoming requests have no authority.
type ApprovalVerifier struct {
	operator ed25519.PublicKey
	security ed25519.PublicKey
}

func NewApprovalVerifier(operator, security ed25519.PublicKey) (*ApprovalVerifier, error) {
	if len(operator) != ed25519.PublicKeySize || len(security) != ed25519.PublicKeySize ||
		bytes.Equal(operator, security) {
		return nil, ErrApprovalDenied
	}
	return &ApprovalVerifier{
		operator: append(ed25519.PublicKey(nil), operator...),
		security: append(ed25519.PublicKey(nil), security...),
	}, nil
}

// ApprovalMessage is the only canonical byte representation for signing.
// Fixed Go struct field order, explicit domain separation and strict fields
// prevent changing the environment, action, account, version or audit binding
// after either signature has been made.
func ApprovalMessage(a SuspensionApproval) ([]byte, error) {
	if a.Environment != "staging" || a.Action != SuspendAndRevokeAction ||
		!subjectPattern.MatchString(a.Subject) ||
		a.ExpectedSessionVersion <= 0 || a.ExpectedSessionVersion == math.MaxInt64 ||
		!approvalIssue.MatchString(a.ReviewIssue) ||
		!approvalSHA256.MatchString(a.EvidenceSHA256) ||
		!approvalNonce.MatchString(a.Nonce) ||
		a.IssuedAt < 1577836800 || a.ExpiresAt > 4102444800 ||
		a.ExpiresAt <= a.IssuedAt ||
		a.ExpiresAt-a.IssuedAt > int64(approvalLifetime.Seconds()) {
		return nil, ErrApprovalDenied
	}
	body, err := json.Marshal(a)
	if err != nil {
		return nil, ErrApprovalDenied
	}
	message := make([]byte, 0, len(approvalDomain)+len(body))
	message = append(message, approvalDomain...)
	message = append(message, body...)
	return message, nil
}

// Verify proves that both *configured* authorities signed the exact same
// short-lived staging suspension request. It DOES NOT consume the nonce,
// authorize the underlying human, or perform account/session mutation.
// Replays must be prevented by a future transactional command journal.
func (v *ApprovalVerifier) Verify(s SignedSuspension, now time.Time) error {
	if v == nil || len(v.operator) != ed25519.PublicKeySize ||
		len(v.security) != ed25519.PublicKeySize ||
		bytes.Equal(v.operator, v.security) || now.IsZero() ||
		len(s.OperatorSignature) != ed25519.SignatureSize ||
		len(s.SecuritySignature) != ed25519.SignatureSize {
		return ErrApprovalDenied
	}
	message, err := ApprovalMessage(s.Approval)
	if err != nil {
		return ErrApprovalDenied
	}
	epoch := now.UTC().Unix()
	if epoch < s.Approval.IssuedAt-int64(approvalClockSkew.Seconds()) ||
		epoch >= s.Approval.ExpiresAt {
		return ErrApprovalDenied
	}
	if !ed25519.Verify(v.operator, message, s.OperatorSignature) ||
		!ed25519.Verify(v.security, message, s.SecuritySignature) {
		return ErrApprovalDenied
	}
	return nil
}
