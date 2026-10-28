package composer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"

	"golang.org/x/crypto/sha3"
)

// Hash is a 32-byte digest. It prints as 0x-prefixed lowercase hex.
type Hash [32]byte

// Hex returns the 0x-prefixed lowercase hex form.
func (h Hash) Hex() string { return "0x" + hex.EncodeToString(h[:]) }

func (h Hash) String() string { return h.Hex() }

// IsZero reports whether every byte is zero.
func (h Hash) IsZero() bool { return h == Hash{} }

// MarshalText implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.Hex()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(b []byte) error {
	v, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

var (
	hash32Re   = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	addressRe  = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	zeroDigest = "sha256:" + fmt.Sprintf("%064d", 0)
)

// ParseHash parses a 0x-prefixed lowercase 32-byte hex string.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if !hash32Re.MatchString(s) {
		return h, fmt.Errorf("%q is not 0x-prefixed lowercase hex of 32 bytes", s)
	}
	_, _ = hex.Decode(h[:], []byte(s[2:]))
	return h, nil
}

// Address is a 20-byte account address. JSON and hashes use lowercase hex.
type Address [20]byte

// Hex returns the 0x-prefixed lowercase hex form.
func (a Address) Hex() string { return "0x" + hex.EncodeToString(a[:]) }

func (a Address) String() string { return a.Hex() }

// ParseAddress parses a 0x-prefixed lowercase 20-byte hex string. Checksummed
// (mixed-case) input is rejected so that one address has one JSON encoding.
func ParseAddress(s string) (Address, error) {
	var a Address
	if !addressRe.MatchString(s) {
		return a, fmt.Errorf("%q is not a 0x-prefixed lowercase 20-byte address", s)
	}
	_, _ = hex.Decode(a[:], []byte(s[2:]))
	return a, nil
}

// SHA256 hashes b.
func SHA256(b []byte) Hash { return sha256.Sum256(b) }

// Keccak256 hashes the concatenation of parts with legacy Keccak-256 (the
// Ethereum variant, not NIST SHA3-256).
func Keccak256(parts ...[]byte) Hash {
	k := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		k.Write(p)
	}
	var h Hash
	k.Sum(h[:0])
	return h
}

// AppID is keccak256(bytes(slug)).
func AppID(slug string) Hash { return Keccak256([]byte(slug)) }

// ReleaseID is keccak256(abi.encode(appId, version, bundleHash)).
func ReleaseID(appID Hash, version string, bundleHash Hash) Hash {
	return Keccak256(abiEncode(appID, version, bundleHash))
}

// DeploymentID is keccak256(abi.encode(customer, stackHash, salt)).
func DeploymentID(customer Address, stackHash, salt Hash) Hash {
	return Keccak256(abiEncode(customer, stackHash, salt))
}

// ImageID is keccak256(abi.encode(name, version, measurementsHash)).
func ImageID(name, version string, measurementsHash Hash) Hash {
	return Keccak256(abiEncode(name, version, measurementsHash))
}

// MeasurementsHash is keccak256(mrtd || rtmr0 || rtmr1 || rtmr2), each exactly 48 bytes.
func MeasurementsHash(mrtd, rtmr0, rtmr1, rtmr2 []byte) (Hash, error) {
	for i, m := range [][]byte{mrtd, rtmr0, rtmr1, rtmr2} {
		if len(m) != 48 {
			return Hash{}, fmt.Errorf("measurement %d is %d bytes, want 48", i, len(m))
		}
	}
	return Keccak256(mrtd, rtmr0, rtmr1, rtmr2), nil
}

// abiEncode implements Solidity abi.encode for the static types bytes32 and
// address and the dynamic type string, which is all the id formulas need.
func abiEncode(args ...any) []byte {
	head := make([]byte, 0, 32*len(args))
	var tail []byte
	for _, a := range args {
		switch v := a.(type) {
		case Hash:
			head = append(head, v[:]...)
		case Address:
			head = append(head, make([]byte, 12)...)
			head = append(head, v[:]...)
		case string:
			head = append(head, uint256(uint64(32*len(args)+len(tail)))...)
			tail = append(tail, uint256(uint64(len(v)))...)
			tail = append(tail, v...)
			if pad := (32 - len(v)%32) % 32; pad > 0 {
				tail = append(tail, make([]byte, pad)...)
			}
		default:
			panic(fmt.Sprintf("abiEncode: unsupported type %T", a))
		}
	}
	return append(head, tail...)
}

func uint256(n uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], n)
	return b
}
