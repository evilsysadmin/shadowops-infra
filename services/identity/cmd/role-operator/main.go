// role-operator is an offline-only staging adapter. It does not provision
// credentials, establish trust roots, access the backup vault, or expose HTTP.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/roles"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var errConfiguration = errors.New("invalid operator configuration")

type connector func(string) (*mongo.Client, error)

// Only explicitly understood TLS options are accepted. In particular the
// driver must never be allowed to disable certificate or hostname checking.
func validateURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "mongodb" && u.Scheme != "mongodb+srv") || u.Host == "" || u.User == nil || u.Fragment != "" {
		return errConfiguration
	}
	password, ok := u.User.Password()
	if !ok || password == "" || u.User.Username() == "" {
		return errConfiguration
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errConfiguration
	}
	allowed := map[string]bool{"tls": true, "replicaset": true, "authsource": true, "directconnection": true, "tlscafile": true}
	seen := map[string]bool{}
	for key, value := range values {
		normalized := strings.ToLower(key)
		if !allowed[normalized] || seen[normalized] || len(value) != 1 || value[0] == "" {
			return errConfiguration
		}
		seen[normalized] = true
		if normalized == "tls" && value[0] != "true" {
			return errConfiguration
		}
	}
	if u.Scheme == "mongodb+srv" && (u.Port() != "" || strings.Contains(u.Host, ",") || seen["directconnection"]) {
		return errConfiguration
	}
	if !seen["tls"] {
		return errConfiguration
	}
	return nil
}
func publicKey(raw string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize || hex.EncodeToString(b) != raw {
		return nil, errConfiguration
	}
	return ed25519.PublicKey(b), nil
}

// run receives its connector and configuration separately to keep tests
// isolated. It never returns driver errors which may contain credentials.
func run(ctx context.Context, args []string, getenv func(string) string, input io.Reader, connect connector) error {
	if len(args) != 1 || (args[0] != "schema" && args[0] != "bootstrap" && args[0] != "change") || getenv("IDENTITY_ROLE_ENVIRONMENT") != "staging" {
		return errConfiguration
	}
	uri := getenv("IDENTITY_ROLE_MONGO_URI")
	if err := validateURI(uri); err != nil {
		return errConfiguration
	}
	var keyA, keyB ed25519.PublicKey
	if args[0] != "schema" {
		var err error
		keyA, err = publicKey(getenv("IDENTITY_ROLE_TRUSTED_KEY_A"))
		if err != nil {
			return errConfiguration
		}
		keyB, err = publicKey(getenv("IDENTITY_ROLE_TRUSTED_KEY_B"))
		if err != nil {
			return errConfiguration
		}
	}
	client, err := connect(uri)
	if err != nil || client == nil {
		return errors.New("role operation failed")
	}
	defer client.Disconnect(context.Background())
	switch args[0] {
	case "schema":
		err = roles.PrepareStagingRoleJournalIndex(ctx, client)
	case "bootstrap":
		err = roles.ApplyBootstrapRequest(ctx, client, keyA, keyB, input)
	case "change":
		err = roles.ApplyRoleChangeRequest(ctx, client, keyA, keyB, input)
	}
	if err != nil {
		return errors.New("role operation failed")
	}
	return nil
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := run(ctx, os.Args[1:], os.Getenv, os.Stdin, func(uri string) (*mongo.Client, error) { return mongo.Connect(options.Client().ApplyURI(uri)) })
	if err != nil {
		fmt.Fprintln(os.Stderr, "staging role operator: operation rejected or unavailable")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "staging role operator: operation completed")
}
