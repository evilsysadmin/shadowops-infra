package main

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"strings"
	"testing"
)

func TestURIRequiresAuthenticatedTLSWithoutUnsafeOptions(t *testing.T) {
	tests := []struct {
		uri   string
		valid bool
	}{
		{"mongodb://user:password@db.example/?tls=true&authSource=admin", true},
		{"mongodb://user:password@db.example/?tls=false", false}, {"mongodb://user:password@db.example/", false}, {"mongodb://db.example/?tls=true", false},
		{"mongodb://user:password@db.example/?tls=true&tlsInsecure=true", false}, {"mongodb://user:password@db.example/?tls=true&TLS=false", false},
		{"mongodb://user:password@db.example/?tls=true&tlsAllowInvalidCertificates=true", false}, {"mongodb://user:password@db.example/?tls=true&unknown=1", false},
	}
	for _, test := range tests {
		if (validateURI(test.uri) == nil) != test.valid {
			t.Fatalf("wrong result for %q", test.uri)
		}
	}
}
func TestCommandRejectsUnsafeConfigurationAndHidesErrors(t *testing.T) {
	env := map[string]string{"IDENTITY_ROLE_ENVIRONMENT": "production", "IDENTITY_ROLE_MONGO_URI": "mongodb://user:secret@db.example/?tls=true"}
	get := func(k string) string { return env[k] }
	called := false
	connect := func(string) (*mongo.Client, error) { called = true; return nil, errors.New("driver secret") }
	if err := run(context.Background(), []string{"schema"}, get, strings.NewReader(""), connect); err == nil || called {
		t.Fatal("unsafe environment reached connector")
	}
	env["IDENTITY_ROLE_ENVIRONMENT"] = "staging"
	if err := run(context.Background(), []string{"change"}, get, strings.NewReader("{}"), connect); err == nil || called {
		t.Fatal("missing trust keys reached connector")
	}
	if err := run(context.Background(), []string{"schema"}, get, strings.NewReader(""), connect); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("connector failure exposed details")
	}
}
