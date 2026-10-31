// Package roles defines Identity's own account role vocabulary. These roles
// are NOT application authorizations: each product must enforce its own grants.
package roles

type Role string

const (
	User  Role = "user"
	Admin Role = "admin"
)

// ParseStored accepts legacy missing roles as the least-privileged user. Any
// unknown/noncanonical value is rejected, never upgraded to an admin.
func ParseStored(value string) (Role, bool) {
	switch value {
	case "", string(User):
		return User, true
	case string(Admin):
		return Admin, true
	default:
		return "", false
	}
}

// SelfRegistrationRole is a fixed default. The browser's request cannot
// specify or influence an elevated role during enrollment.
func SelfRegistrationRole() Role { return User }

// GrantsApplicationAdmin intentionally remains false for BOTH Identity roles:
// a central admin may administer Identity but is not silently the owner of
// every game, Kubernetes lab or tenant.
func GrantsApplicationAdmin(Role) bool { return false }
