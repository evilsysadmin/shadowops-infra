package issuance

import "context"

// CKAPoCSigner preserves the original CKA-only API, with no audience selector.
type CKAPoCSigner struct{ app *StagingAppSigner }

const ckaAudience = "cka-simulator"
const ckaPoCTokenLifetime = appTokenLifetime

type ckaPOCClaims = appTokenClaims

func NewCKAPoCSigner(issuer *Issuer, seed []byte) (*CKAPoCSigner, error) {
	app, err := NewStagingAppSigner(issuer, seed, CKASimulator)
	if err != nil {
		return nil, err
	}
	return &CKAPoCSigner{app: app}, nil
}
func (s *CKAPoCSigner) JWKS() ([]byte, error) {
	if s == nil || s.app == nil {
		return nil, ErrDenied
	}
	return s.app.JWKS()
}
func (s *CKAPoCSigner) IssuePoCToken(ctx context.Context, handle string) (string, error) {
	if s == nil || s.app == nil {
		return "", ErrDenied
	}
	return s.app.IssueToken(ctx, handle)
}
