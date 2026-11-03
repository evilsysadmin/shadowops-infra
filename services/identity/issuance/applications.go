package issuance

// Application is fixed trusted server configuration, never a user role.
type Application string

const (
	ChessStudio  Application = "chess-studio"
	Chronicles   Application = "chronicles"
	CKASimulator Application = "cka-simulator"
	Football     Application = "football"
	PawnAction   Application = "pawn-action"
)

func (a Application) valid() bool {
	switch a {
	case ChessStudio, Chronicles, CKASimulator, Football, PawnAction:
		return true
	}
	return false
}
