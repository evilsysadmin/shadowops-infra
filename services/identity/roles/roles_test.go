package roles

import "testing"

func TestIdentityRoleVocabulary(t *testing.T) {
	for _, tc := range []struct {
		value string
		role  Role
		ok    bool
	}{
		{"", User, true}, // existing account without role -> least privilege
		{"user", User, true},
		{"admin", Admin, true},
		{"Admin", "", false},
		{"ADMIN", "", false},
		{"owner", "", false},
		{"root", "", false},
		{"user,admin", "", false},
		{" user ", "", false},
		{"*", "", false},
		{"\x00admin", "", false},
	} {
		got, ok := ParseStored(tc.value)
		if got != tc.role || ok != tc.ok {
			t.Fatalf("ParseStored(%q)=%q,%v want=%q,%v", tc.value, got, ok, tc.role, tc.ok)
		}
	}
	if SelfRegistrationRole() != User {
		t.Fatal("self registration escalated privilege")
	}
	for _, role := range []Role{User, Admin, "owner", ""} {
		if GrantsApplicationAdmin(role) {
			t.Fatalf("Identity role %q gave game/tenant admin", role)
		}
	}
}
