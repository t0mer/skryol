package backup

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/keys"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/shodan"
)

const keyA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const keyB = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"

func newInstance(t *testing.T, name, encKey string) (*db.DB, *crypto.Cipher, *keys.Service) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(context.Background(), filepath.Join(dir, name+".db"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	cipher, err := crypto.New(encKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := shodan.NewKeyPool(1)
	keySvc := keys.NewService(database, cipher, pool, slog.Default())
	return database, cipher, keySvc
}

func TestExportImport_PassphrasePortsSecretsAcrossKeys(t *testing.T) {
	ctx := context.Background()

	// Instance A holds a Shodan key with a real secret.
	dbA, cipherA, keysA := newInstance(t, "a", keyA)
	if _, err := keysA.Create(ctx, "primary", "SUPER-SECRET-KEY", true, 1); err != nil {
		t.Fatal(err)
	}
	asset := &models.Asset{Type: models.AssetIP, Value: "1.2.3.4", Label: "edge", Enabled: true}
	_ = asset.Validate()
	if err := dbA.CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}

	backupA := NewService(dbA, cipherA, keysA)
	bundle, err := backupA.Export(ctx, ExportOptions{Mode: ModePassphrase, Passphrase: "correct-horse"})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Salt == "" || len(bundle.ShodanKeys) != 1 || bundle.ShodanKeys[0].Ciphertext == "" {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}

	// Instance B has a DIFFERENT encryption key.
	dbB, cipherB, keysB := newInstance(t, "b", keyB)
	backupB := NewService(dbB, cipherB, keysB)

	// Wrong passphrase must fail.
	if _, err := backupB.Import(ctx, bundle, ImportOptions{Passphrase: "nope"}); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}

	// Correct passphrase imports and re-encrypts under B's key.
	res, err := backupB.Import(ctx, bundle, ImportOptions{Passphrase: "correct-horse"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created["shodan_keys"] != 1 || res.Created["assets"] != 1 {
		t.Fatalf("unexpected import result: %+v", res)
	}

	// The imported secret must decrypt under B's instance key.
	rows, err := dbB.ListShodanKeys(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 imported key, got %d (%v)", len(rows), err)
	}
	secret, err := cipherB.DecryptString(rows[0].Ciphertext)
	if err != nil {
		t.Fatalf("imported secret does not decrypt under B's key: %v", err)
	}
	if secret != "SUPER-SECRET-KEY" {
		t.Fatalf("secret corrupted across re-encryption: %q", secret)
	}
}

func TestImport_InstanceKeyFingerprintMismatch(t *testing.T) {
	ctx := context.Background()
	dbA, cipherA, keysA := newInstance(t, "a", keyA)
	if _, err := keysA.Create(ctx, "k", "SECRET", true, 1); err != nil {
		t.Fatal(err)
	}
	bundle, err := NewService(dbA, cipherA, keysA).Export(ctx, ExportOptions{Mode: ModeInstanceKey})
	if err != nil {
		t.Fatal(err)
	}
	// Different key -> fingerprint mismatch must be rejected.
	dbB, cipherB, keysB := newInstance(t, "b", keyB)
	if _, err := NewService(dbB, cipherB, keysB).Import(ctx, bundle, ImportOptions{}); err == nil {
		t.Fatal("expected fingerprint mismatch to reject import")
	}
}

func TestExportImport_NoneModeDisablesSecrets(t *testing.T) {
	ctx := context.Background()
	dbA, cipherA, keysA := newInstance(t, "a", keyA)
	if _, err := keysA.Create(ctx, "k", "SECRET", true, 1); err != nil {
		t.Fatal(err)
	}
	bundle, err := NewService(dbA, cipherA, keysA).Export(ctx, ExportOptions{Mode: ModeNone})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ShodanKeys[0].Ciphertext != "" {
		t.Fatal("none mode must omit secrets")
	}
	dbB, cipherB, keysB := newInstance(t, "b", keyB)
	if _, err := NewService(dbB, cipherB, keysB).Import(ctx, bundle, ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	rows, _ := dbB.ListShodanKeys(ctx)
	if len(rows) != 1 || rows[0].Enabled {
		t.Fatalf("none-mode key should import disabled: %+v", rows)
	}
}
