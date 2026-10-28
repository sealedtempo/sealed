package composer

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// The bundle tar is written by hand rather than with archive/tar so its bytes
// can never change with a Go release: POSIX ustar headers, entries sorted by
// path, explicit parent directories, mtime 0, uid/gid 0, empty uname/gname,
// mode 0644 for files and 0755 for directories, two zero blocks at the end
// and no record padding.

const (
	blockSize      = 512
	maxBundleBytes = 64 << 20
	maxBundleFiles = 4096
	maxFileBytes   = 32 << 20
)

// WriteTar returns the deterministic tar of files. Keys are slash-separated
// relative paths. Text files must already be LF-normalized (see
// NormalizeText); WriteTar does not change content.
func WriteTar(files map[string][]byte) ([]byte, error) {
	entries, err := tarEntries(files)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, e := range entries {
		hdr, err := ustarHeader(e.name, e.dir, int64(len(e.data)))
		if err != nil {
			return nil, err
		}
		buf.Write(hdr)
		buf.Write(e.data)
		if pad := (blockSize - len(e.data)%blockSize) % blockSize; pad > 0 {
			buf.Write(make([]byte, pad))
		}
	}
	buf.Write(make([]byte, 2*blockSize))
	return buf.Bytes(), nil
}

type tarEntry struct {
	name string // directories end in "/"
	dir  bool
	data []byte
}

func tarEntries(files map[string][]byte) ([]tarEntry, error) {
	if len(files) > maxBundleFiles {
		return nil, fmt.Errorf("bundle: too many files (%d)", len(files))
	}
	dirs := map[string]bool{}
	var entries []tarEntry
	for name, data := range files {
		if err := checkBundlePath(name); err != nil {
			return nil, err
		}
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			dirs[d+"/"] = true
		}
		entries = append(entries, tarEntry{name: name, data: data})
	}
	for d := range dirs {
		if _, clash := files[strings.TrimSuffix(d, "/")]; clash {
			return nil, fmt.Errorf("bundle: %q is both a file and a directory", strings.TrimSuffix(d, "/"))
		}
		entries = append(entries, tarEntry{name: d, dir: true})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries, nil
}

func checkBundlePath(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") ||
		strings.Contains(name, "\\") || path.Clean(name) != name || name == "." ||
		strings.HasPrefix(name, "../") || !utf8.ValidString(name) {
		return fmt.Errorf("bundle: invalid path %q", name)
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("bundle: invalid path %q", name)
		}
	}
	return nil
}

func ustarHeader(name string, dir bool, size int64) ([]byte, error) {
	h := make([]byte, blockSize)
	prefix, short, err := splitUstarName(name)
	if err != nil {
		return nil, err
	}
	copy(h[0:100], short)
	mode, typ := int64(0o644), byte('0')
	if dir {
		mode, typ = 0o755, '5'
	}
	putOctal(h[100:108], mode)
	putOctal(h[108:116], 0) // uid
	putOctal(h[116:124], 0) // gid
	putOctal(h[124:136], size)
	putOctal(h[136:148], 0) // mtime
	h[156] = typ
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	// uname (265:297) and gname (297:329) stay empty.
	putOctal(h[329:337], 0) // devmajor
	putOctal(h[337:345], 0) // devminor
	copy(h[345:500], prefix)
	copy(h[148:156], "        ")
	var sum int64
	for _, b := range h {
		sum += int64(b)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return h, nil
}

// putOctal writes n as zero-padded octal digits followed by a NUL.
func putOctal(field []byte, n int64) {
	s := fmt.Sprintf("%0*o", len(field)-1, n)
	copy(field, s)
	field[len(field)-1] = 0
}

func splitUstarName(name string) (prefix, short string, err error) {
	if len(name) <= 100 {
		return "", name, nil
	}
	for i := len(name) - 1; i > 0; i-- {
		if name[i] != '/' {
			continue
		}
		p, n := name[:i], name[i+1:]
		if len(p) <= 155 && len(n) <= 100 && n != "" {
			return p, n, nil
		}
	}
	return "", "", fmt.Errorf("bundle: path %q is too long for ustar", name)
}

// ReadTar parses a bundle tar and returns its regular files. It accepts only
// the canonical form WriteTar produces: rewriting the parsed files must give
// back the exact input bytes, so one bundleHash names exactly one content.
func ReadTar(data []byte) (map[string][]byte, error) {
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("bundle: larger than %d bytes", maxBundleBytes)
	}
	tr := tar.NewReader(bytes.NewReader(data))
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("bundle: %q: only regular files and directories are allowed", hdr.Name)
		}
		if hdr.Size > maxFileBytes {
			return nil, fmt.Errorf("bundle: %q is too large", hdr.Name)
		}
		if _, dup := files[hdr.Name]; dup {
			return nil, fmt.Errorf("bundle: duplicate entry %q", hdr.Name)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("bundle: %q: %w", hdr.Name, err)
		}
		files[hdr.Name] = b
		if len(files) > maxBundleFiles {
			return nil, fmt.Errorf("bundle: too many files")
		}
	}
	again, err := WriteTar(files)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, data) {
		return nil, fmt.Errorf("bundle: not in canonical form (rebuild it with sealed release build)")
	}
	return files, nil
}

// NormalizeText converts CRLF and lone CR line endings to LF in text files.
// A file is text when it is valid UTF-8 and has no NUL byte.
func NormalizeText(b []byte) []byte {
	if !isText(b) || !bytes.ContainsRune(b, '\r') {
		return b
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
}

func isText(b []byte) bool {
	return utf8.Valid(b) && !bytes.ContainsRune(b, 0)
}
