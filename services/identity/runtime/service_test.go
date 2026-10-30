package runtime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
	"github.com/evilsysadmin/shadowops-infra/services/identity/websession"
)

func syntheticServiceConfig(t *testing.T) ServiceConfig {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral Identity unit CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: serviceHost}, DNSNames: []string{serviceHost}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	root := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	return ServiceConfig{Environment: "staging", MongoURI: "mongodb://fixture:synthetic-password@127.0.0.1:27019/shadowops_identity_staging?tls=true", MongoCA: root, SigningSeed: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32)), TLSCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + root, TLSPrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})), Consumers: websession.ConsumerCredentials{issuance.Chronicles: "soc1_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x88}, 32))}}
}

func TestServiceConfigUsesPrivateRegularExplicitStagingBundle(t *testing.T) {
	cfg := syntheticServiceConfig(t)
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadServiceConfig(filename); err != nil || loaded.Environment != "staging" {
		t.Fatal("valid scoped configuration denied", err)
	}
	if err := os.Chmod(filename, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServiceConfig(filename); err == nil {
		t.Fatal("world-readable private bundle accepted")
	}
	if err := os.Chmod(filename, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(filename), "symlink.json")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServiceConfig(link); err == nil {
		t.Fatal("symlink private bundle accepted")
	}
	if _, err := LoadServiceConfig("runtime.json"); err == nil {
		t.Fatal("relative private bundle accepted")
	}
	for _, bad := range [][]byte{append(bytes.Clone(data), []byte(" {}")...), append([]byte(`{"unknown":true,`), data[1:]...), bytes.Repeat([]byte("x"), 131073)} {
		if err := os.WriteFile(filename, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServiceConfig(filename); err == nil {
			t.Fatal("unsafe or ambiguous private JSON accepted")
		}
	}
}

func TestServiceConfigDeniesCrossEnvironmentAndInsecureMongoTLS(t *testing.T) {
	base := syntheticServiceConfig(t)
	for name, change := range map[string]func(*ServiceConfig){
		"production":          func(c *ServiceConfig) { c.Environment = "production" },
		"missing environment": func(c *ServiceConfig) { c.Environment = "" },
		"production database": func(c *ServiceConfig) {
			c.MongoURI = "mongodb://fixture:password@127.0.0.1:27019/shadowops_identity_production?tls=true"
		},
		"unauthenticated": func(c *ServiceConfig) { c.MongoURI = "mongodb://127.0.0.1:27019/?tls=true" },
		"plaintext":       func(c *ServiceConfig) { c.MongoURI = "mongodb://fixture:password@127.0.0.1:27019/?tls=false" },
		"invalid cert bypass": func(c *ServiceConfig) {
			c.MongoURI = "mongodb://fixture:password@127.0.0.1:27019/?tlsAllowInvalidCertificates=true"
		},
		"missing seed":     func(c *ServiceConfig) { c.SigningSeed = "" },
		"missing TLS key":  func(c *ServiceConfig) { c.TLSPrivateKey = "" },
		"missing consumer": func(c *ServiceConfig) { c.Consumers = nil },
		"user proof as consumer": func(c *ServiceConfig) {
			c.Consumers = websession.ConsumerCredentials{issuance.Chronicles: "user-jwt-or-cookie"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			change(&cfg)
			if _, _, _, err := cfg.validate(time.Now()); err == nil {
				t.Fatal("unsafe staging configuration accepted")
			}
		})
	}
}
