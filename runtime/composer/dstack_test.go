package composer

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/sealed-dev/sealed/runtime/composer/cjson"
)

// These reproduce runtime/composer/testdata/dstack/vectors.py (dstack v0.6.1
// event log rules, docs/notes/dstack.md section 6.3) in Go, with the sample
// app-compose serialized by our own CJSON encoder.

const dstackEventType = 0x08000001

func v1Preimage(name string, payload []byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, dstackEventType)
	b = append(b, ':')
	b = append(b, name...)
	b = append(b, ':')
	return append(b, payload...)
}

func v2Preimage(t *testing.T, name string, payload []byte) []byte {
	b, err := cjson.Encode(map[string]any{"name": name, "payload": hex.EncodeToString(payload), "type": int64(dstackEventType)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replay(digests [][]byte, newHash func() hash.Hash, size int) []byte {
	mr := make([]byte, size)
	for _, d := range digests {
		hh := newHash()
		hh.Write(mr)
		hh.Write(d)
		mr = hh.Sum(nil)
	}
	return mr
}

func sum384(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
func sum256(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func hexEq(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s:\n got %x\nwant %s", what, got, want)
	}
}

func TestDstackGoldenVectors(t *testing.T) {
	pre := v1Preimage("app-id", []byte{0xde, 0xad, 0xbe, 0xef})
	hexEq(t, "v1 preimage", pre, "010000083a6170702d69643adeadbeef")
	hexEq(t, "v1 sha384", sum384(pre), "67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f")

	v2 := v2Preimage(t, "compose-hash", []byte{0xab, 0xcd})
	if string(v2) != `{"name":"compose-hash","payload":"abcd","type":134217729}` {
		t.Errorf("v2 preimage %s", v2)
	}
	hexEq(t, "v2 sha384", sum384(v2), "9dde1673f544faa94b921825209593ddde08d0baf9cd6990175dffaf3081f1bb10311d56de189491feb33842a050ad7b")

	compose := map[string]any{
		"manifest_version":    2,
		"name":                "hello",
		"runner":              "docker-compose",
		"docker_compose_file": "services:\n  web:\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
		"gateway_enabled":     false,
		"kms_enabled":         false,
		"key_provider":        "none",
		"public_logs":         true,
		"public_sysinfo":      true,
		"public_tcbinfo":      true,
		"allowed_envs":        []any{},
		"no_instance_id":      false,
		"secure_time":         false,
		"storage_fs":          "ext4",
	}
	cb, err := cjson.Encode(compose)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := `{"allowed_envs":[],"docker_compose_file":"services:\n  web:\n    image: nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000\n","gateway_enabled":false,"key_provider":"none","kms_enabled":false,"manifest_version":2,"name":"hello","no_instance_id":false,"public_logs":true,"public_sysinfo":true,"public_tcbinfo":true,"runner":"docker-compose","secure_time":false,"storage_fs":"ext4"}`
	if string(cb) != wantBytes {
		t.Fatalf("compose bytes\n got %s\nwant %s", cb, wantBytes)
	}
	ch := sum256(cb)
	hexEq(t, "compose sha256", ch, "a06cf4774c792a56cdb756e773d0acf5d508332376982dc8a1e70811d33377e4")

	gpu := sum256([]byte("{}"))
	hexEq(t, "gpu-policy-hash", gpu, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a")

	appID := make([]byte, 20)
	instanceID := make([]byte, 20)
	for i := range appID {
		appID[i], instanceID[i] = 0x11, 0x33
	}
	events := []struct {
		name    string
		payload []byte
	}{
		{"system-preparing", nil},
		{"app-id", appID},
		{"compose-hash", ch},
		{"gpu-policy-hash", gpu},
		{"instance-id", instanceID},
		{"boot-mr-done", nil},
		{"key-provider", []byte(`{"name":"none","id":""}`)},
		{"storage-fs", []byte("ext4")},
		{"storage-encrypted", []byte("1")},
		{"system-ready", nil},
	}
	var d384, d256 [][]byte
	for _, e := range events {
		p := v1Preimage(e.name, e.payload)
		d384 = append(d384, sum384(p))
		d256 = append(d256, sum256(p))
	}
	hexEq(t, "RTMR3", replay(d384, sha512.New384, 48), "30498094c86fca91569d7ea7dc79fcfd7dfbf7ac699a1fde8b673f659e1f0fcc08ee73fdccd5eb000694689b212822d1")
	hexEq(t, "RTMR3 to boot-mr-done", replay(d384[:6], sha512.New384, 48), "5087565e0705ebbd36500f414ef35cff648b28d342eb1b2ac370909e46e866c19b817bec801d0877960febdb4283b00d")
	hexEq(t, "PCR14", replay(d256, sha256.New, 32), "36a3bb0ce3090811a01bd035cfa6c2e6610cb20662f7061500d7637ebb9b4ac2")
}

// TestStackHashIsComposeHash checks the composed app-compose against the
// dstack rule: compose-hash is sha256 of the exact file bytes.
func TestStackHashIsComposeHash(t *testing.T) {
	cfg, bundles := fixtureStack(t)
	r := mustCompose(t, cfg, bundles...)
	if SHA256(r.AppCompose) != r.StackHash {
		t.Fatal("stackHash must be sha256(app-compose.json)")
	}
	again, err := cjson.Canonicalize(r.AppCompose)
	if err != nil || string(again) != string(r.AppCompose) {
		t.Fatalf("app-compose.json must already be canonical: %v", err)
	}
}
