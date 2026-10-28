// Package fatimg writes the small FAT16 volume dstack reads its host-shared files from on Google Cloud: a disk
// whose filesystem label is DSTACKSHR, holding app-compose.json, .sys-config.json and .instance_info in the root
// directory (docs/notes/dstack.md section 4.3). The output is deterministic: fixed volume id, fixed timestamps,
// files in name order, long file names (VFAT) so the names survive exactly.
package fatimg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf16"
)

const (
	sectorSize        = 512
	sectorsPerCluster = 4 // 2 KiB clusters
	reservedSectors   = 1
	numFATs           = 2
	rootEntries       = 512
	rootSectors       = rootEntries * 32 / sectorSize
	totalSectors      = 32768 // 16 MiB
	fatSectors        = 32    // 8192 FAT16 entries
	dataStart         = reservedSectors + numFATs*fatSectors + rootSectors
	clusterCount      = (totalSectors - dataStart) / sectorsPerCluster
	clusterBytes      = sectorsPerCluster * sectorSize
	volumeID          = 0x5EA1ED00
)

// Label is the filesystem label dstack looks for.
const Label = "DSTACKSHR"

// Size is the volume size in bytes.
const Size = totalSectors * sectorSize

// MaxFileSize bounds one file (the volume holds about 16 MiB of data).
const MaxFileSize = (clusterCount - 8) * clusterBytes

// Build returns the FAT16 volume holding files in its root directory. Names are at most 64 characters of
// printable ASCII without / \ : * ? " < > |.
func Build(files map[string][]byte) ([]byte, error) {
	if len(files) == 0 || len(files) > 32 {
		return nil, errors.New("fatimg: between 1 and 32 files")
	}
	names := make([]string, 0, len(files))
	total := 0
	for n, b := range files {
		if err := checkName(n); err != nil {
			return nil, err
		}
		if len(b) > MaxFileSize {
			return nil, fmt.Errorf("fatimg: %s is too large", n)
		}
		total += (len(b) + clusterBytes - 1) / clusterBytes
		names = append(names, n)
	}
	if total > clusterCount {
		return nil, errors.New("fatimg: files do not fit")
	}
	sort.Strings(names)

	img := make([]byte, Size)
	writeBootSector(img[:sectorSize])
	fat := make([]uint16, fatSectors*sectorSize/2)
	fat[0], fat[1] = 0xFFF8, 0xFFFF
	root := img[(reservedSectors+numFATs*fatSectors)*sectorSize : dataStart*sectorSize]

	// Volume label entry first.
	var label [11]byte
	copy(label[:], padRight(Label, 11))
	entry := dirEntry(label, 0x08, 0, 0)
	copy(root, entry[:])
	slot := 1

	next := uint16(2)
	for i, n := range names {
		data := files[n]
		first := uint16(0)
		if len(data) > 0 {
			first = next
			clusters := (len(data) + clusterBytes - 1) / clusterBytes
			for c := 0; c < clusters; c++ {
				cl := next + uint16(c)
				off := (dataStart + int(cl-2)*sectorsPerCluster) * sectorSize
				end := (c + 1) * clusterBytes
				if end > len(data) {
					end = len(data)
				}
				copy(img[off:], data[c*clusterBytes:end])
				if c == clusters-1 {
					fat[cl] = 0xFFFF
				} else {
					fat[cl] = cl + 1
				}
			}
			next += uint16(clusters)
		}
		short := shortName(i)
		lfn := lfnEntries(n, checksum(short))
		if slot+len(lfn)+1 > rootEntries {
			return nil, errors.New("fatimg: root directory full")
		}
		for _, e := range lfn {
			copy(root[slot*32:], e[:])
			slot++
		}
		e := dirEntry(short, 0x20, first, uint32(len(data)))
		copy(root[slot*32:], e[:])
		slot++
	}
	for f := 0; f < numFATs; f++ {
		off := (reservedSectors + f*fatSectors) * sectorSize
		for i, v := range fat {
			binary.LittleEndian.PutUint16(img[off+2*i:], v)
		}
	}
	return img, nil
}

func checkName(n string) error {
	if n == "" || len(n) > 64 || n == "." || n == ".." {
		return fmt.Errorf("fatimg: invalid file name %q", n)
	}
	for _, r := range n {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("fatimg: file name %q must be printable ASCII", n)
		}
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return fmt.Errorf("fatimg: file name %q has a reserved character", n)
		}
	}
	return nil
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func writeBootSector(b []byte) {
	copy(b[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(b[3:11], "SEALED  ")
	binary.LittleEndian.PutUint16(b[11:], sectorSize)
	b[13] = sectorsPerCluster
	binary.LittleEndian.PutUint16(b[14:], reservedSectors)
	b[16] = numFATs
	binary.LittleEndian.PutUint16(b[17:], rootEntries)
	binary.LittleEndian.PutUint16(b[19:], totalSectors)
	b[21] = 0xF8 // fixed disk
	binary.LittleEndian.PutUint16(b[22:], fatSectors)
	binary.LittleEndian.PutUint16(b[24:], 32) // sectors per track
	binary.LittleEndian.PutUint16(b[26:], 64) // heads
	binary.LittleEndian.PutUint32(b[28:], 0)  // hidden sectors
	binary.LittleEndian.PutUint32(b[32:], 0)  // total sectors (32-bit), unused
	b[36] = 0x80                              // drive number
	b[38] = 0x29                              // extended boot signature
	binary.LittleEndian.PutUint32(b[39:], volumeID)
	copy(b[43:54], padRight(Label, 11))
	copy(b[54:62], "FAT16   ")
	// Not bootable: the boot code halts.
	b[62], b[63] = 0xF4, 0xEB
	b[64] = 0xFD
	b[510], b[511] = 0x55, 0xAA
}

// shortName is a valid, unique 8.3 alias. Linux and dstack read the long names.
func shortName(i int) [11]byte {
	var s [11]byte
	copy(s[:], padRight(fmt.Sprintf("SHRF~%d", i+1), 8)+"BIN")
	return s
}

func checksum(short [11]byte) byte {
	var sum byte
	for _, c := range short {
		sum = ((sum & 1) << 7) + (sum >> 1) + c
	}
	return sum
}

// Fixed timestamp: 1980-01-01 00:00:00.
const fatDate = 1<<5 | 1

func dirEntry(name [11]byte, attr byte, cluster uint16, size uint32) [32]byte {
	var e [32]byte
	copy(e[0:11], name[:])
	e[11] = attr
	binary.LittleEndian.PutUint16(e[16:], fatDate) // creation date
	binary.LittleEndian.PutUint16(e[18:], fatDate) // last access date
	binary.LittleEndian.PutUint16(e[24:], fatDate) // write date
	binary.LittleEndian.PutUint16(e[26:], cluster)
	binary.LittleEndian.PutUint32(e[28:], size)
	return e
}

// lfnEntries returns the VFAT long name entries in on-disk order (last part first).
func lfnEntries(name string, sum byte) [][32]byte {
	u := utf16.Encode([]rune(name))
	n := (len(u) + 12) / 13
	padded := make([]uint16, n*13)
	for i := range padded {
		switch {
		case i < len(u):
			padded[i] = u[i]
		case i == len(u):
			padded[i] = 0x0000
		default:
			padded[i] = 0xFFFF
		}
	}
	out := make([][32]byte, 0, n)
	for seq := n; seq >= 1; seq-- {
		var e [32]byte
		ord := byte(seq)
		if seq == n {
			ord |= 0x40
		}
		e[0] = ord
		e[11] = 0x0F
		e[13] = sum
		part := padded[(seq-1)*13 : seq*13]
		offs := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
		for i, o := range offs {
			binary.LittleEndian.PutUint16(e[o:], part[i])
		}
		out = append(out, e)
	}
	return out
}
