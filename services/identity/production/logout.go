package production

import (
 "context"
)

// Logout deletes the exact production session digest only after verifying the
// currently active account and session version. Deleting a session invalidates
// every associated application-token JTI at the next freshness check.
func (a *AccountAuthority) Logout(ctx context.Context, handle string) error {
 if !a.ready(ctx) { return ErrAccountDenied }
 digest,ok:=productionHandleDigest(handle)
 if !ok { return ErrAccountDenied }
 if _,err:=a.Validate(ctx,handle);err!=nil { return ErrAccountDenied }
 if err:=a.sessions.Delete(ctx,"production",digest);err!=nil { return ErrAccountStore }
 return nil
}
