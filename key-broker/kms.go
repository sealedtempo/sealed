package keybroker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Domain tags of the two derived keys (INTERFACES.md section 9, D-011).
const (
	DiskKeyTag    = "sealed/disk/v1"
	SignerSeedTag = "sealed/signer/v1"
)

// MACSigner computes HMAC-SHA256 with the customer's key. In production it is the bootstrap's Cloud KMS MAC key
// (key-broker/gcp.KMSMAC), so the root key never leaves KMS. Locally it is a file-backed key (LocalHMAC).
type MACSigner interface {
	MAC(ctx context.Context, data []byte) ([]byte, error)
}

// DerivedKeys are the per-deployment keys a release carries. They depend only on the MAC key and the deploymentId, so
// a rebooted deployment gets the same disk key and enclave signer (A11).
type DerivedKeys struct {
	DiskKey    [32]byte
	SignerSeed [32]byte
}

// DeriveKeys computes diskKey = HMAC("sealed/disk/v1" || deploymentId) and
// signerSeed = HMAC("sealed/signer/v1" || deploymentId).
func DeriveKeys(ctx context.Context, m MACSigner, deploymentID [32]byte) (DerivedKeys, error) {
	var out DerivedKeys
	for _, k := range []struct {
		tag string
		dst *[32]byte
	}{{DiskKeyTag, &out.DiskKey}, {SignerSeedTag, &out.SignerSeed}} {
		msg := append([]byte(k.tag), deploymentID[:]...)
		mac, err := m.MAC(ctx, msg)
		if err != nil {
			return DerivedKeys{}, fmt.Errorf("%s: %w", k.tag, err)
		}
		if len(mac) != 32 {
			return DerivedKeys{}, fmt.Errorf("%s: MAC is %d bytes, want 32 (HMAC-SHA256)", k.tag, len(mac))
		}
		copy(k.dst[:], mac)
	}
	if out.DiskKey == out.SignerSeed {
		return DerivedKeys{}, errors.New("derived keys are equal; the MAC signer ignores its input")
	}
	return out, nil
}

// LocalHMAC is a MACSigner over a key held in memory. It is the local stand-in for Cloud KMS.
type LocalHMAC struct {
	key []byte
}

// NewLocalHMAC returns a MACSigner over key (at least 32 bytes).
func NewLocalHMAC(key []byte) (*LocalHMAC, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("HMAC key is %d bytes, want at least 32", len(key))
	}
	return &LocalHMAC{key: append([]byte(nil), key...)}, nil
}

// MAC implements MACSigner.
func (l *LocalHMAC) MAC(_ context.Context, data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, l.key)
	h.Write(data)
	return h.Sum(nil), nil
}

// LoadOrCreateFileHMAC reads a hex-encoded HMAC key from path, or creates a random 32-byte one there (mode 0600).
// Dev only: the cmd refuses it outside a dev build with SEALED_DEV_SIM=1.
func LoadOrCreateFileHMAC(path string) (*LocalHMAC, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create dev HMAC key: %w", err)
		}
		if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return NewLocalHMAC(key)
	}
	if err != nil {
		return nil, fmt.Errorf("read dev HMAC key: %w", err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("dev HMAC key %s is readable by others (mode %v); chmod 600 it", path, info.Mode().Perm())
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("dev HMAC key %s is not hex", path)
	}
	return NewLocalHMAC(key)
}
