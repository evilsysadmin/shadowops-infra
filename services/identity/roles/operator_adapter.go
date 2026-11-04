package roles

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// The adapter accepts a signed request, never signing keys or a connection
// string. Callers must supply independently provisioned Mongo clients and
// pinned public keys. It does not discover or provision credentials.
var ErrOperatorRequest = errors.New("invalid staging role operator request")

const maxOperatorRequestBytes = 16 * 1024

type bootstrapRequest struct {
	Statement           RoleBootstrapStatement `json:"statement"`
	AuthorityASignature []byte                 `json:"authority_a_signature"`
	AuthorityBSignature []byte                 `json:"authority_b_signature"`
	OperatorProof       []byte                 `json:"operator_proof"`
	SecurityProof       []byte                 `json:"security_proof"`
}

type changeRequest struct {
	Change            RoleChange `json:"change"`
	OperatorSignature []byte     `json:"operator_signature"`
	SecuritySignature []byte     `json:"security_signature"`
}

// inspectJSON rejects duplicate keys, including nested duplicates. Go's JSON
// decoder otherwise accepts them and lets the last value win.
func inspectJSON(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrOperatorRequest
			}
			for previous := range seen {
				if strings.EqualFold(previous, key) {
					return ErrOperatorRequest
				}
			}
			seen[key] = true
			if err := inspectJSON(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return ErrOperatorRequest
		}
	case '[':
		for dec.More() {
			if err := inspectJSON(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return ErrOperatorRequest
		}
	default:
		return ErrOperatorRequest
	}
	return nil
}

func decodeOperatorRequest(input io.Reader, target any) error {
	if input == nil {
		return ErrOperatorRequest
	}
	data, err := io.ReadAll(io.LimitReader(input, maxOperatorRequestBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxOperatorRequestBytes {
		return ErrOperatorRequest
	}
	check := json.NewDecoder(bytes.NewReader(data))
	if err := inspectJSON(check); err != nil {
		return ErrOperatorRequest
	}
	if _, err := check.Token(); err != io.EOF {
		return ErrOperatorRequest
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return ErrOperatorRequest
	}
	return nil
}

// ApplyBootstrapRequest validates an independently signed genesis request and
// runs the existing one-time bootstrap transaction. Authorities come from
// trusted configuration, never from the request.
func ApplyBootstrapRequest(ctx context.Context, client *mongo.Client, authorityA, authorityB ed25519.PublicKey, input io.Reader) error {
	var request bootstrapRequest
	if err := decodeOperatorRequest(input, &request); err != nil {
		return err
	}
	bootstrap, err := NewStagingRoleBootstrapper(ctx, client, authorityA, authorityB)
	if err != nil {
		return err
	}
	return bootstrap.Bootstrap(ctx, SignedRoleBootstrap{Statement: request.Statement, AuthorityASignature: request.AuthorityASignature, AuthorityBSignature: request.AuthorityBSignature, OperatorProof: request.OperatorProof, SecurityProof: request.SecurityProof})
}

// ApplyRoleChangeRequest invokes only the existing signed, audited role
// transaction. The trusted signer keys are supplied outside the request.
func ApplyRoleChangeRequest(ctx context.Context, client *mongo.Client, operator, security ed25519.PublicKey, input io.Reader) error {
	var request changeRequest
	if err := decodeOperatorRequest(input, &request); err != nil {
		return err
	}
	executor, err := NewStagingRoleExecutor(ctx, client, operator, security)
	if err != nil {
		return err
	}
	return executor.ApplyApprovedRoleChange(ctx, SignedRoleChange{Change: request.Change, OperatorSignature: request.OperatorSignature, SecuritySignature: request.SecuritySignature})
}
