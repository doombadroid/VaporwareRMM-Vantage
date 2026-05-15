// Package signing holds Vantage's drill-through-SSO signing
// keypair. F2's enrollment-bundle handler ships the public key to
// every paired Edge; F5 will use the private key to sign 5-minute
// SSO JWTs that Edges validate offline against the same public key.
//
// The keypair is generated on first boot (Bootstrap) and reused on
// subsequent boots. Private key is AES-GCM encrypted at rest via
// the crypto package; public key is plaintext PEM so the handler
// can return it directly.
//
// Multi-node note (#22 Q10): the keypair sits in Postgres, not in
// any process-local file or memory cache. A second Vantage node
// boots, finds the row, and decrypts the same private key. There
// is no per-node keypair; all Vantage instances sign with the same
// identity so Edges can validate any drill-through JWT regardless
// of which node served it.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"vaporrmm/vantage/internal/crypto"
	"vaporrmm/vantage/internal/db"
)

var (
	mu         sync.RWMutex
	privateKey ed25519.PrivateKey
	publicPEM  string
)

// Bootstrap loads the existing signing keypair or generates one
// if the table is empty. Idempotent + concurrency-safe — multiple
// Vantage nodes starting in parallel each propose their own
// candidate keypair; ON CONFLICT DO NOTHING lets the database pick
// one winner; every node then SELECTs the winning row.
//
// Per #22 Q10: cross-process state lives in Postgres, never in
// per-node memory. A multi-node startup race in the original
// (SELECT then INSERT) code caused all-but-one nodes to crash on
// PK violation. Codex finding #5 flagged this.
func Bootstrap() error {
	// Generate a candidate keypair. If another node beats us to
	// the INSERT, this candidate is silently discarded — Ed25519
	// generation is cheap (<1ms), so the race-lost work is
	// negligible.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("signing: generate ed25519: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("signing: marshal pkcs8: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("signing: marshal pkix: %w", err)
	}
	candidatePrivPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	candidatePubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	encryptedCandidatePriv, err := crypto.Encrypt(string(candidatePrivPEM))
	if err != nil {
		return fmt.Errorf("signing: encrypt candidate private key: %w", err)
	}

	// ON CONFLICT DO NOTHING: if the row already exists, this is a
	// no-op. The follow-up SELECT then loads the winning keypair —
	// which may be the one we just inserted, or one inserted by
	// another node, or one persisted on a prior boot.
	if _, err := db.DB.Exec(
		`INSERT INTO vantage_signing_key (id, private_key_encrypted, public_key, algorithm, created_at)
		     VALUES ('singleton', $1, $2, 'Ed25519', $3)
		     ON CONFLICT (id) DO NOTHING`,
		encryptedCandidatePriv, string(candidatePubPEM), time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("signing: insert candidate keypair: %w", err)
	}

	var pubPEM, encPriv string
	if err := db.DB.QueryRow(
		`SELECT public_key, private_key_encrypted FROM vantage_signing_key WHERE id = 'singleton'`,
	).Scan(&pubPEM, &encPriv); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("signing: vantage_signing_key row missing after upsert")
		}
		return fmt.Errorf("signing: read keypair row: %w", err)
	}

	loadedPriv, err := loadPrivate(encPriv)
	if err != nil {
		return fmt.Errorf("signing: load winning keypair: %w", err)
	}

	mu.Lock()
	privateKey = loadedPriv
	publicPEM = pubPEM
	mu.Unlock()

	if pubPEM == string(candidatePubPEM) {
		slog.Info("signing: generated new Ed25519 keypair")
	} else {
		slog.Info("signing: loaded existing Ed25519 keypair (race-lost or prior boot)")
	}
	return nil
}

// PublicKeyPEM returns the PEM-encoded public key. Empty string
// before Bootstrap has run.
func PublicKeyPEM() string {
	mu.RLock()
	defer mu.RUnlock()
	return publicPEM
}

// Sign produces an Ed25519 signature over msg. F5 will use this to
// sign drill-through JWTs. Returns an error if Bootstrap hasn't run.
func Sign(msg []byte) ([]byte, error) {
	mu.RLock()
	priv := privateKey
	mu.RUnlock()
	if priv == nil {
		return nil, errors.New("signing: keypair not loaded; call Bootstrap first")
	}
	return ed25519.Sign(priv, msg), nil
}

// ResetForTests wipes the in-memory keys so a test can re-bootstrap
// against a fresh DB row. Test-only.
func ResetForTests() {
	mu.Lock()
	privateKey = nil
	publicPEM = ""
	mu.Unlock()
}

func loadPrivate(encryptedPEM string) (ed25519.PrivateKey, error) {
	decPEM, err := crypto.Decrypt(encryptedPEM)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	block, _ := pem.Decode([]byte(decPEM))
	if block == nil {
		return nil, errors.New("pem decode returned nil block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T (want ed25519.PrivateKey)", parsed)
	}
	return priv, nil
}
