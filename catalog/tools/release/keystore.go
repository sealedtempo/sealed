package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
)

// Scrypt parameters of the throwaway keystore. The password is 32 random bytes that live next to it for
// the length of one script run, so the light parameters cost nothing in strength.
const (
	ksScryptN = 1 << 12
	ksScryptR = 8
	ksScryptP = 6
)

// WriteKeystore encrypts the secp256k1 key held in the environment variable keyEnv into a Web3 v3 keystore
// in dir (keystore.json, mode 0600) with a random password (password, mode 0600), and returns the address.
// Scripts then pass --keystore and --password-file to cast, so the raw key never appears in a command line
// (process listings show arguments, not the environment).
func WriteKeystore(keyEnv, dir string) (string, error) {
	raw := strings.TrimSpace(os.Getenv(keyEnv))
	if raw == "" {
		return "", fmt.Errorf("%s is not set", keyEnv)
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X"))
	if err != nil {
		return "", fmt.Errorf("%s is not a secp256k1 private key in hex", keyEnv)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	pw := make([]byte, 32)
	salt := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	id := make([]byte, 16)
	for _, b := range [][]byte{pw, salt, iv, id} {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
	}
	password := hex.EncodeToString(pw)
	derived, err := scrypt.Key([]byte(password), salt, ksScryptN, ksScryptR, ksScryptP, 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return "", err
	}
	priv := padTo32(key.D)
	ciphertext := make([]byte, len(priv))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, priv)
	mac := crypto.Keccak256(derived[16:32], ciphertext)
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	doc := map[string]any{
		"address": strings.ToLower(strings.TrimPrefix(addr.Hex(), "0x")),
		"crypto": map[string]any{
			"cipher":       "aes-128-ctr",
			"ciphertext":   hex.EncodeToString(ciphertext),
			"cipherparams": map[string]string{"iv": hex.EncodeToString(iv)},
			"kdf":          "scrypt",
			"kdfparams":    map[string]any{"dklen": 32, "n": ksScryptN, "p": ksScryptP, "r": ksScryptR, "salt": hex.EncodeToString(salt)},
			"mac":          hex.EncodeToString(mac),
		},
		"id":      fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:]),
		"version": 3,
	}
	ks, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	if err := writeSecret(filepath.Join(dir, "password"), []byte(password)); err != nil {
		return "", err
	}
	if err := writeSecret(filepath.Join(dir, "keystore.json"), ks); err != nil {
		return "", err
	}
	return strings.ToLower(addr.Hex()), nil
}

func padTo32(d *big.Int) []byte {
	out := make([]byte, 32)
	b := d.Bytes()
	copy(out[32-len(b):], b)
	return out
}

func writeSecret(p string, b []byte) error {
	tmp := fmt.Sprintf("%s.%d.tmp", p, time.Now().UnixNano())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
