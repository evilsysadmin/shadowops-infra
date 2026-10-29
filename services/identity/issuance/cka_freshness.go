package issuance

import "context"

// StagingCKAFreshness preserves the original CKA evidence shape and audience.
type StagingCKAFreshness struct{ app *StagingAppFreshness }

func NewStagingCKAFreshness(issuer *Issuer) (*StagingCKAFreshness, error) {
	app, err := NewStagingAppFreshness(issuer, CKASimulator)
	if err != nil {
		return nil, err
	}
	return &StagingCKAFreshness{app: app}, nil
}
func (c *StagingCKAFreshness) Check(ctx context.Context, sub string, version int64, jti string) (SessionFreshnessEvidence, error) {
	if c == nil || c.app == nil {
		return SessionFreshnessEvidence{}, ErrDenied
	}
	evidence, err := c.app.Check(ctx, sub, version, jti)
	return evidence.SessionFreshnessEvidence, err
}
func tokenDigest(jti string) string { return tokenDigestFor(CKASimulator, jti) }
