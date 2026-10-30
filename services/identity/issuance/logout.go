package issuance

import "context"

// Logout removes one central session using the store's majority write concern.
// All bound application tokens fail their next freshness check. Other browser
// sessions are unaffected. Unknown canonical handles are idempotently accepted.
// Cookie/CSRF handling belongs to the separate websession transport.
func (i *Issuer) Logout(ctx context.Context, handle string) error {
	if i == nil || i.sessions == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	digest, ok := stagingHandleDigest(handle)
	if !ok {
		return ErrDenied
	}
	if err := i.sessions.Delete(ctx, "staging", digest); err != nil {
		return ErrStore
	}
	return nil
}
