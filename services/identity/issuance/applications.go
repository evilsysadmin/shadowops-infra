package issuance

// Application is fixed trusted server configuration, never a user role.
type Application string

const (
	ChessStudio    Application = "chess-studio"
	Chronicles     Application = "chronicles"
	CKASimulator   Application = "cka-simulator"
	Football       Application = "football"
	PawnAction     Application = "pawn-action"
	Snooker        Application = "snooker"
	StarAdventures Application = "staradvs"
)

func (a Application) valid() bool {
	switch a {
	case ChessStudio, Chronicles, CKASimulator, Football, PawnAction, Snooker, StarAdventures:
		return true
	}
	return false
}
