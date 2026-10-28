package fatimg

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// readVolume is an independent minimal FAT16 reader: boot sector geometry, root directory with VFAT names,
// cluster chains.
func readVolume(t *testing.T, img []byte) (label string, files map[string][]byte) {
	t.Helper()
	le16 := func(o int) int { return int(binary.LittleEndian.Uint16(img[o:])) }
	if img[510] != 0x55 || img[511] != 0xAA {
		t.Fatal("no boot signature")
	}
	bps, spc, rsvd, nfats, rootEnt, fatSz := le16(11), int(img[13]), le16(14), int(img[16]), le16(17), le16(22)
	if string(img[54:62]) != "FAT16   " {
		t.Fatalf("fs type %q", img[54:62])
	}
	label = strings.TrimRight(string(img[43:54]), " ")
	fat0 := rsvd * bps
	if !bytes.Equal(img[fat0:fat0+fatSz*bps], img[fat0+fatSz*bps:fat0+2*fatSz*bps]) {
		t.Fatal("the two FAT copies differ")
	}
	rootOff := (rsvd + nfats*fatSz) * bps
	dataOff := rootOff + rootEnt*32
	files = map[string][]byte{}
	var lfn []uint16
	for i := 0; i < rootEnt; i++ {
		e := img[rootOff+i*32 : rootOff+i*32+32]
		if e[0] == 0 {
			break
		}
		attr := e[11]
		switch {
		case attr == 0x0F:
			var part []uint16
			for _, o := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				part = append(part, binary.LittleEndian.Uint16(e[o:]))
			}
			lfn = append(part, lfn...)
		case attr&0x08 != 0:
			if got := strings.TrimRight(string(e[:11]), " "); got != label {
				t.Fatalf("label entry %q, boot sector %q", got, label)
			}
		default:
			var name []uint16
			for _, c := range lfn {
				if c == 0 {
					break
				}
				name = append(name, c)
			}
			lfn = nil
			size := int(binary.LittleEndian.Uint32(e[28:]))
			cl := int(binary.LittleEndian.Uint16(e[26:]))
			var data []byte
			for size > 0 && cl >= 2 && cl < 0xFFF8 {
				off := dataOff + (cl-2)*spc*bps
				data = append(data, img[off:off+spc*bps]...)
				cl = int(binary.LittleEndian.Uint16(img[fat0+2*cl:]))
			}
			if len(data) < size {
				t.Fatalf("chain shorter than size")
			}
			files[string(utf16.Decode(name))] = data[:size]
		}
	}
	return label, files
}

func sample() map[string][]byte {
	big := bytes.Repeat([]byte(`{"k":"v"}`), 3000) // spans many clusters
	return map[string][]byte{
		"app-compose.json": big,
		".sys-config.json": []byte(`{"gateway_urls":[],"kms_urls":[],"pccs_url":"","vm_config":"{}"}`),
		".instance_info":   []byte(`{"instance_id_seed":"0011223344556677889900112233445566778899"}`),
		"empty":            {},
	}
}

func TestRoundTrip(t *testing.T) {
	in := sample()
	img, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(img) != Size {
		t.Fatalf("size %d", len(img))
	}
	label, got := readVolume(t, img)
	if label != "DSTACKSHR" {
		t.Fatalf("label %q", label)
	}
	if len(got) != len(in) {
		t.Fatalf("files %v", got)
	}
	for n, b := range in {
		if !bytes.Equal(got[n], b) {
			t.Fatalf("%s differs", n)
		}
	}
	again, _ := Build(sample())
	if !bytes.Equal(img, again) {
		t.Fatal("not deterministic")
	}
}

func TestRejects(t *testing.T) {
	for name, files := range map[string]map[string][]byte{
		"none":     {},
		"slash":    {"a/b": nil},
		"nonascii": {"é": nil},
		"too big":  {"x": make([]byte, MaxFileSize+1)},
	} {
		if _, err := Build(files); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestSystemFsck checks the volume with the platform's FAT checker when one is installed (fsck_msdos on macOS,
// fsck.fat from dosfstools on Linux).
func TestSystemFsck(t *testing.T) {
	img, err := Build(sample())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shared.raw")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tool := range [][]string{{"fsck_msdos", "-n"}, {"fsck.fat", "-n", "-v"}} {
		if _, err := exec.LookPath(tool[0]); err != nil {
			continue
		}
		out, err := exec.Command(tool[0], append(tool[1:], path)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", tool[0], err, out)
		}
		if bytes.Contains(bytes.ToLower(out), []byte("error")) || bytes.Contains(bytes.ToLower(out), []byte("invalid")) {
			t.Fatalf("%s reported problems:\n%s", tool[0], out)
		}
		t.Logf("%s:\n%s", tool[0], out)
		return
	}
	t.Skip("no fsck_msdos or fsck.fat installed")
}
