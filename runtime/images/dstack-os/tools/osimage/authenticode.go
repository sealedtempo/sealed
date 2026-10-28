// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
)

// authenticode returns the PE/COFF Authenticode digest of a PE32 or PE32+ image with the given hash. It follows
// dstack's os/image/authenticode_hash.py byte for byte (headers without the checksum and certificate directory,
// sections in file order, trailing data without the certificate table, zero padding to 8 bytes), which is the
// digest UEFI firmware extends into the TPM PCR4 / TDX RTMR1 event for a boot application. The sha256 variant is
// dstack's gcp_uki_auth; the sha384 variant is what a TDX RTMR1 event log should carry for BOOTX64.EFI.
func authenticode(data []byte, newHash func() hash.Hash) ([]byte, error) {
	u16 := func(off int) (int, error) {
		if off < 0 || off+2 > len(data) {
			return 0, errors.New("truncated PE image")
		}
		return int(binary.LittleEndian.Uint16(data[off:])), nil
	}
	u32 := func(off int) (int, error) {
		if off < 0 || off+4 > len(data) {
			return 0, errors.New("truncated PE image")
		}
		return int(binary.LittleEndian.Uint32(data[off:])), nil
	}
	lfanew, err := u32(0x3c)
	if err != nil {
		return nil, err
	}
	sig, err := u32(lfanew)
	if err != nil {
		return nil, err
	}
	if sig != 0x00004550 {
		return nil, errors.New("not a PE image (no PE signature)")
	}
	coff := lfanew + 4
	optSize, err := u16(coff + 16)
	if err != nil {
		return nil, err
	}
	opt := coff + 20
	magic, err := u16(opt)
	if err != nil {
		return nil, err
	}
	checksum := opt + 64
	dataDir := opt + 96
	if magic == 0x20b {
		dataDir = opt + 112
	}
	certDir := dataDir + 4*8
	headers, err := u32(opt + 60)
	if err != nil {
		return nil, err
	}
	if certDir+8 > headers || headers > len(data) {
		return nil, errors.New("malformed PE headers")
	}
	h := newHash()
	h.Write(data[:checksum])
	h.Write(data[checksum+4 : certDir])
	h.Write(data[certDir+8 : headers])
	hashed := headers

	nsec, err := u16(coff + 2)
	if err != nil {
		return nil, err
	}
	type span struct{ off, size int }
	var spans []span
	for i := 0; i < nsec; i++ {
		s := opt + optSize + i*40
		size, err := u32(s + 16)
		if err != nil {
			return nil, err
		}
		off, err := u32(s + 20)
		if err != nil {
			return nil, err
		}
		if size > 0 {
			spans = append(spans, span{off, size})
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
	for _, s := range spans {
		end := s.off + s.size
		if end > len(data) {
			end = len(data)
		}
		if s.off < end {
			h.Write(data[s.off:end])
		}
		hashed += s.size
	}
	certAddr, err := u32(certDir)
	if err != nil {
		return nil, err
	}
	certSize, err := u32(certDir + 4)
	if err != nil {
		return nil, err
	}
	if certAddr > 0 && certSize > 0 && len(data) > hashed {
		trailing := len(data) - hashed
		if trailing > certSize {
			n := trailing - certSize
			if hashed+n <= len(data) {
				h.Write(data[hashed : hashed+n])
			}
		}
	}
	if r := len(data) % 8; r != 0 {
		h.Write(make([]byte, 8-r))
	}
	return h.Sum(nil), nil
}

func hashByName(name string) (func() hash.Hash, error) {
	switch name {
	case "sha256":
		return sha256.New, nil
	case "sha384":
		return sha512.New384, nil
	default:
		return nil, fmt.Errorf("unsupported hash %q (sha256 or sha384)", name)
	}
}

func cmdAuthenticode(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("authenticode", flag.ContinueOnError)
	alg := fs.String("alg", "sha256", "sha256 or sha384")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: osimage authenticode [-alg sha256|sha384] FILE")
	}
	newHash, err := hashByName(*alg)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sum, err := authenticode(data, newHash)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, hex.EncodeToString(sum))
	return err
}
