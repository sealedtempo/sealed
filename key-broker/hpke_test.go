package keybroker_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"

	keybroker "github.com/sealed-dev/sealed/key-broker"
)

var updateVectors = flag.Bool("update", false, "rewrite testdata/hpke-kb-release-vector.json")

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHPKEVectorFromCore opens the fixed vectors @sealed/core tests (packages/core/test/fixtures/hpke-vector.json):
// one sealed by @hpke/core in TypeScript, one by Go crypto/hpke. Both use info sealed/kb-release/v1 and a 32-byte aad,
// exactly a key release.
func TestHPKEVectorFromCore(t *testing.T) {
	raw, err := os.ReadFile(repoPath(t, "packages", "core", "test", "fixtures", "hpke-vector.json"))
	if err != nil {
		t.Fatalf("the shared HPKE vector of @sealed/core is missing: %v", err)
	}
	var v struct {
		IKM, EphemeralIKM, Info, AAD, RecipientPublicKey, TSPlaintext, TSWire, GoPlaintext, GoWire string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Info != keybroker.ReleaseInfo {
		t.Fatalf("vector info %q", v.Info)
	}
	priv, pub, err := keybroker.DeriveEphemeralKey(mustHex(t, v.IKM))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(pub[:]) != v.RecipientPublicKey {
		t.Fatalf("DeriveKeyPair gives %x, vector has %s", pub, v.RecipientPublicKey)
	}
	aad := [32]byte(mustHex(t, v.AAD))
	for _, c := range []struct{ wire, want string }{{v.TSWire, v.TSPlaintext}, {v.GoWire, v.GoPlaintext}} {
		w := mustHex(t, c.wire)
		pt, err := keybroker.OpenRelease(priv, aad, w[:32], w[32:])
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != c.want {
			t.Fatalf("plaintext %q, want %q", pt, c.want)
		}
		// Another nonce (aad) must not open it.
		other := aad
		other[0] ^= 1
		if _, err := keybroker.OpenRelease(priv, other, w[:32], w[32:]); err == nil {
			t.Fatal("opened with another nonce")
		}
	}
}

type releaseVector struct {
	Description  string `json:"description"`
	RecipientIKM string `json:"recipientIkm"`
	EphemeralPub string `json:"ephemeralPub"`
	Nonce        string `json:"nonce"`
	Info         string `json:"info"`
	Plaintext    string `json:"plaintext"`
	Enc          string `json:"enc"`
	Ciphertext   string `json:"ciphertext"`
}

const vectorPath = "testdata/hpke-kb-release-vector.json"

func sealVector(t *testing.T) releaseVector {
	cryptotest.SetGlobalRandom(t, 4217)
	ikm := bytes.Repeat([]byte{0x01}, 32)
	_, pub, err := keybroker.DeriveEphemeralKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	nonce := [32]byte(bytes.Repeat([]byte{0xab}, 32))
	pt := `{"diskKey":"0x` + strings.Repeat("11", 32) + `","secrets":{"_gate":{"GATE_PASSWORD_BCRYPT":"$2a$04$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"},"crm":{"APP_SECRET":"crm secret ✓"}},"signerSeed":"0x` + strings.Repeat("22", 32) + `"}`
	enc, ct, err := keybroker.SealRelease(pub, nonce, []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	return releaseVector{
		Description:  "Key broker release (INTERFACES.md 9): HPKE base mode DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM, info sealed/kb-release/v1, aad = nonce, enc and ciphertext as separate fields. The recipient key is DeriveKeyPair(recipientIkm). Sealed by key-broker SealRelease with Go crypto/hpke under testing/cryptotest seed 4217. Regenerate with go test ./key-broker -run TestHPKEReleaseVector -update.",
		RecipientIKM: hex.EncodeToString(ikm),
		EphemeralPub: "0x" + hex.EncodeToString(pub[:]),
		Nonce:        "0x" + hex.EncodeToString(nonce[:]),
		Info:         keybroker.ReleaseInfo,
		Plaintext:    pt,
		Enc:          "0x" + hex.EncodeToString(enc),
		Ciphertext:   "0x" + hex.EncodeToString(ct),
	}
}

// TestHPKEReleaseVector pins the key broker's own release encryption as a fixed vector file that other
// implementations test against, and checks the Go side reproduces and opens it.
func TestHPKEReleaseVector(t *testing.T) {
	var got releaseVector
	t.Run("seal", func(t *testing.T) { got = sealVector(t) })
	if *updateVectors {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(vectorPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var want releaseVector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("SealRelease no longer reproduces %s (run with -update only if the change is intended)", vectorPath)
	}
	priv, _, err := keybroker.DeriveEphemeralKey(mustHex(t, want.RecipientIKM))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := keybroker.OpenRelease(priv, [32]byte(mustHex(t, want.Nonce)), mustHex(t, want.Enc), mustHex(t, want.Ciphertext))
	if err != nil || string(pt) != want.Plaintext {
		t.Fatalf("open: %v %q", err, pt)
	}
	if len(mustHex(t, want.Enc)) != 32 || len(mustHex(t, want.Ciphertext)) != len(want.Plaintext)+16 {
		t.Fatal("enc must be 32 bytes and the ciphertext the bare AEAD output")
	}
}

// TestHPKEInteropWithCore opens the key broker's vector with @sealed/core's TypeScript openKbRelease, the code
// sealed-agent runs. It needs node and a built packages/core (pnpm --filter @sealed/core build); it skips without
// them unless SEALED_REQUIRE_NODE=1.
func TestHPKEInteropWithCore(t *testing.T) {
	node, err := exec.LookPath("node")
	dist := repoPath(t, "packages", "core", "dist", "hpke.js")
	_, distErr := os.Stat(dist)
	if err != nil || distErr != nil {
		if os.Getenv("SEALED_REQUIRE_NODE") == "1" {
			t.Fatalf("SEALED_REQUIRE_NODE=1 but node (%v) or %s (%v) is missing", err, dist, distErr)
		}
		t.Skip("node or a built @sealed/core is missing")
	}
	vec, _ := filepath.Abs(vectorPath)
	script, _ := filepath.Abs("testdata/core-open-release.mjs")
	out, err := exec.Command(node, script, dist, vec).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var v releaseVector
	raw, _ := os.ReadFile(vectorPath)
	_ = json.Unmarshal(raw, &v)
	if string(out) != v.Plaintext {
		t.Fatalf("@sealed/core opened %q, want %q", out, v.Plaintext)
	}
}

// TestSealReleaseRejectsLowOrderKey: an all-zero X25519 key has no usable shared secret.
func TestSealReleaseRejectsLowOrderKey(t *testing.T) {
	if _, _, err := keybroker.SealRelease([32]byte{}, [32]byte{1}, []byte("x")); err == nil {
		t.Fatal("sealed to the all-zero public key")
	}
}
