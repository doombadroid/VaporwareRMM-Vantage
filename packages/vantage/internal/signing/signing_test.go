package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

const testEncryptionKey = "fmZn0pFd/f58gKeknlaECEbcMDh5oQ+nRhFB/sAMScY="

func setup(t *testing.T) {
	t.Helper()
	url := os.Getenv("VANTAGE_TEST_PG_URL")
	if url == "" {
		t.Skip("set VANTAGE_TEST_PG_URL to a Postgres connection string")
	}
	if err := crypto.SetKeyForTests(testEncryptionKey); err != nil {
		t.Fatalf("crypto SetKeyForTests: %v", err)
	}
	t.Setenv("DATABASE_URL", url)
	conn, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, _ = conn.Exec(`DROP TABLE IF EXISTS tailscale_connection, vantage_signing_key, enrollment_tokens, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
	_ = conn.Close()
	t.Cleanup(func() {
		if db.DB != nil {
			_, _ = db.DB.Exec(`DROP TABLE IF EXISTS tailscale_connection, vantage_signing_key, enrollment_tokens, audit_log, user_sessions, users, edges, schema_migrations CASCADE`)
			_ = db.DB.Close()
			db.DB = nil
		}
		ResetForTests()
	})
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
}

// TestBootstrap_GeneratesAndPersists: first call inserts a row;
// the public key returned is a parseable PEM Ed25519 public key.
func TestBootstrap_GeneratesAndPersists(t *testing.T) {
	setup(t)

	if err := Bootstrap(); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	pub := PublicKeyPEM()
	if !strings.Contains(pub, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key not PEM-encoded: %q", pub)
	}

	block, _ := pem.Decode([]byte(pub))
	if block == nil {
		t.Fatal("pem decode returned nil")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pkix: %v", err)
	}
	if _, ok := parsed.(ed25519.PublicKey); !ok {
		t.Errorf("expected ed25519.PublicKey, got %T", parsed)
	}

	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM vantage_signing_key`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 keypair row, got %d", count)
	}
}

// TestBootstrap_ReusesPersistedKey: second Bootstrap call reads
// the same row, producing the same public key.
func TestBootstrap_ReusesPersistedKey(t *testing.T) {
	setup(t)

	if err := Bootstrap(); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	first := PublicKeyPEM()

	ResetForTests()
	if err := Bootstrap(); err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	second := PublicKeyPEM()

	if first != second {
		t.Error("Bootstrap should reuse persisted keypair, got different public keys across boots")
	}
}

// TestSign_ProducesVerifiableSignature: signed msg verifies against
// the public key.
func TestSign_ProducesVerifiableSignature(t *testing.T) {
	setup(t)
	if err := Bootstrap(); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	msg := []byte("drill-through-jwt-payload")
	sig, err := Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := PublicKeyPEM()
	block, _ := pem.Decode([]byte(pub))
	parsed, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pubKey := parsed.(ed25519.PublicKey)

	if !ed25519.Verify(pubKey, msg, sig) {
		t.Error("signature did not verify against persisted public key")
	}
}

// TestBootstrap_EncryptsPrivateKeyAtRest: the stored row's
// private_key_encrypted column begins with the crypto package's
// "enc:" prefix and does NOT contain the literal "BEGIN PRIVATE KEY"
// header that would indicate plaintext.
func TestBootstrap_EncryptsPrivateKeyAtRest(t *testing.T) {
	setup(t)
	if err := Bootstrap(); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	var encPriv string
	if err := db.DB.QueryRow(`SELECT private_key_encrypted FROM vantage_signing_key WHERE id = 'singleton'`).Scan(&encPriv); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encPriv, "enc:") {
		t.Errorf("private key not encrypted at rest (no enc: prefix): %q", encPriv[:20])
	}
	if strings.Contains(encPriv, "BEGIN PRIVATE KEY") {
		t.Error("private key plaintext found in database column")
	}
}
