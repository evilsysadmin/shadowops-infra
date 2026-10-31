package roles

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

// Role changes require an independently reviewed, short-lived operator action.
// This package only validates authorization intent: it NEVER writes Mongo,
// issues sessions, changes an application grant, or exposes a public endpoint.
const (
	SetRoleAction      = "set-role"
	roleApprovalDomain = "shadowops-identity-role-change-v1\n"
	roleApprovalTTL    = 5 * time.Minute
	roleApprovalSkew   = 30 * time.Second
)

var (
	ErrRoleApprovalDenied = errors.New("Identity role change approval denied")
	roleSubjectPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	roleReviewIssue       = regexp.MustCompile(`^https://github\.com/evilsysadmin/shadowops-infra/issues/[1-9][0-9]{0,8}$`)
	roleEvidenceHash      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	roleApprovalNonce     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// RoleChange binds precisely one identity account and expected current role
// to a requested role. Role state and session version must be checked with an
// atomic compare-and-swap and durable, unique nonce journal by any future
// operator-side executor. The reference alone is not ownership evidence.
type RoleChange struct {
	Environment            string `json:"environment"`
	Action                 string `json:"action"`
	Subject                string `json:"subject"`
	From                   Role   `json:"from"`
	To                     Role   `json:"to"`
	ExpectedSessionVersion int64  `json:"expected_session_version"`
	PolicyGeneration       int64  `json:"policy_generation"`
	ReviewIssue            string `json:"review_issue"`
	EvidenceSHA256         string `json:"evidence_sha256"`
	Nonce                  string `json:"nonce"`
	IssuedAt               int64  `json:"issued_at"`
	ExpiresAt              int64  `json:"expires_at"`
}

// SignedRoleChange has explicit, noninterchangeable signer positions. Keys
// must be provisioned independently by a trusted operator, never supplied by
// a login/session or accepted from the change request itself.
type SignedRoleChange struct {
	Change            RoleChange
	OperatorSignature []byte
	SecuritySignature []byte
}

type ApprovalVerifier struct {
	operator ed25519.PublicKey
	security ed25519.PublicKey
}

func NewApprovalVerifier(operator, security ed25519.PublicKey) (*ApprovalVerifier, error) {
	if len(operator) != ed25519.PublicKeySize || len(security) != ed25519.PublicKeySize || bytes.Equal(operator, security) {
		return nil, ErrRoleApprovalDenied
	}
	return &ApprovalVerifier{
		operator: append(ed25519.PublicKey(nil), operator...),
		security: append(ed25519.PublicKey(nil), security...),
	}, nil
}

// ApprovalMessage is domain-separated from all other Identity approvals and
// uses a fixed JSON structure. The caller must not append role changes or
// arbitrary JSON after the signed representation.
func ApprovalMessage(c RoleChange) ([]byte, error) {
	if c.Environment != "staging" || c.Action != SetRoleAction ||
		!roleSubjectPattern.MatchString(c.Subject) ||
		(c.From != User && c.From != Admin) ||
		(c.To != User && c.To != Admin) || c.From == c.To ||
		c.ExpectedSessionVersion < 1 || c.ExpectedSessionVersion == math.MaxInt64 ||
		c.PolicyGeneration < 1 || c.PolicyGeneration == math.MaxInt64 ||
		!roleReviewIssue.MatchString(c.ReviewIssue) ||
		!roleEvidenceHash.MatchString(c.EvidenceSHA256) ||
		!roleApprovalNonce.MatchString(c.Nonce) ||
		c.IssuedAt < 1577836800 || c.ExpiresAt > 4102444800 ||
		c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(roleApprovalTTL.Seconds()) {
		return nil, ErrRoleApprovalDenied
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, ErrRoleApprovalDenied
	}
	message := make([]byte, 0, len(roleApprovalDomain)+len(body))
	message = append(message, roleApprovalDomain...)
	return append(message, body...), nil
}

// Verify is a PURE verifier, not permission to execute. A future executor
// must also check account ownership review, an active pinned signer policy,
// current role/session CAS and nonce uniqueness inside a Mongo transaction.
func (v *ApprovalVerifier) Verify(s SignedRoleChange, now time.Time) error {
	if v == nil || now.IsZero() || len(v.operator) != ed25519.PublicKeySize ||
		len(v.security) != ed25519.PublicKeySize || bytes.Equal(v.operator, v.security) ||
		len(s.OperatorSignature) != ed25519.SignatureSize ||
		len(s.SecuritySignature) != ed25519.SignatureSize {
		return ErrRoleApprovalDenied
	}
	message, err := ApprovalMessage(s.Change)
	if err != nil {
		return ErrRoleApprovalDenied
	}
	instant := now.UTC().Unix()
	if instant < s.Change.IssuedAt-int64(roleApprovalSkew.Seconds()) || instant >= s.Change.ExpiresAt ||
		!ed25519.Verify(v.operator, message, s.OperatorSignature) ||
		!ed25519.Verify(v.security, message, s.SecuritySignature) {
		return ErrRoleApprovalDenied
	}
	return nil
}
