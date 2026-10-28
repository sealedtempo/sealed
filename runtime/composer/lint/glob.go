package lint

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Exclusion patterns: license_exclusions, Options.EnterprisePatterns and
// license_exceptions paths are path globs (license audit F6).
//
//   - "/" separates segments. "*", "?" and "[...]" match within one segment
//     (path.Match); "**" as a whole segment matches zero or more segments.
//   - A leading "/" anchors the pattern at the image root ("/app/enterprise/**").
//     Without it the pattern may start at any segment ("ms-playwright/chromium-*"
//     also matches /root/.cache/ms-playwright/chromium-1187), as if it began with "**/".
//   - A trailing "/" matches directories only: the pattern must match a proper
//     prefix of the path ("ee/" matches /app/server/ee/x.js, not a file named ee).
//   - A pattern that matches a directory covers everything below it, so
//     "**/node_modules/idcac-playwright" covers its package.json.
//   - "owner/repo:path" (for example "BerriAI/litellm:enterprise/") records an
//     upstream source path that is not in any image. It is accepted and never
//     matches.
//
// File paths are compared case-sensitively, as written in the SBOM (syft
// writes them without the leading "/"). Package names are compared
// case-insensitively with "-" and "_" alike, so "**/litellm_enterprise/**"
// matches the PyPI package litellm-enterprise. A package matches when its
// name does (treated as a directory path, so "@anthropic-ai/claude-agent-sdk*"
// matches that npm package) or when one of the files syft names in its
// sourceInfo does (unanchored and anchored patterns alike).
type pathPattern struct {
	raw      string
	segs     []string // "**" first for unanchored patterns
	nsegs    []string // segs normalized for package names
	anchored bool
	dirOnly  bool
	note     bool // upstream source note: never matches image content
	// policy patterns are the D-021 defaults (Options.EnterprisePatterns).
	// They are not applied to OS distribution packages or to files that only
	// OS packages own, which are system components (D-021) and carry, for
	// example, Ewe translations under /usr/share/locale/ee/.
	policy bool
}

var upstreamNoteRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+:[^/\s]\S*$`)

// compilePattern parses one exclusion pattern.
func compilePattern(raw string, policy bool) (*pathPattern, error) {
	s := strings.TrimSpace(raw)
	p := &pathPattern{raw: raw, policy: policy}
	if s == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if upstreamNoteRe.MatchString(s) {
		p.note = true
		return p, nil
	}
	p.anchored = strings.HasPrefix(s, "/")
	p.dirOnly = len(s) > 1 && strings.HasSuffix(s, "/")
	s = strings.TrimSuffix(strings.TrimPrefix(s, "/"), "/")
	if s == "" {
		return nil, fmt.Errorf("%q matches everything", raw)
	}
	var segs []string
	if !p.anchored {
		segs = append(segs, "**")
	}
	for _, seg := range strings.Split(s, "/") {
		switch {
		case seg == "" || seg == "." || seg == "..":
			return nil, fmt.Errorf("%q has an empty, . or .. segment", raw)
		case seg == "**":
			if len(segs) > 0 && segs[len(segs)-1] == "**" {
				continue
			}
		default:
			if _, err := path.Match(seg, ""); err != nil {
				return nil, fmt.Errorf("%q: bad segment %q: %v", raw, seg, err)
			}
		}
		segs = append(segs, seg)
	}
	if len(segs) == 1 && segs[0] == "**" {
		return nil, fmt.Errorf("%q matches everything", raw)
	}
	if len(segs) > 60 {
		return nil, fmt.Errorf("%q has too many segments", raw)
	}
	p.segs = segs
	p.nsegs = make([]string, len(segs))
	for i, seg := range segs {
		p.nsegs[i] = normName(seg)
	}
	return p, nil
}

// normName folds case and treats "_" as "-" (package names).
func normName(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "-") }

// cleanPath normalizes an SBOM file path ("usr/bin/x", "/usr/bin/x",
// "./usr/bin/x") to "usr/bin/x" ("" for the root).
func cleanPath(p string) string {
	return strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "./")), "/")
}

// splitPath turns an SBOM file path into clean segments.
func splitPath(p string) []string {
	if p = cleanPath(p); p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// The matcher is a small NFA over segments: bit j of a state set means
// "pattern segments before j are matched"; bit len(segs) accepts.

// closure adds the positions after "**" segments, which match zero segments.
func closure(states uint64, pat []string) uint64 {
	for j, seg := range pat {
		if states&(1<<j) != 0 && seg == "**" {
			states |= 1 << (j + 1)
		}
	}
	return states
}

// step consumes one path segment.
func step(states uint64, pat []string, seg string) uint64 {
	var next uint64
	for j, ps := range pat {
		if states&(1<<j) == 0 {
			continue
		}
		if ps == "**" {
			next |= 1 << j
		} else if ok, _ := path.Match(ps, seg); ok {
			next |= 1 << (j + 1)
		}
	}
	return closure(next, pat)
}

// matchRoot returns the number of leading segments of the shortest prefix of
// segs the pattern matches, or -1. For a directory-only pattern the prefix
// must be shorter than segs unless whole is true (package names, which are
// directories themselves).
func (p *pathPattern) matchRoot(segs []string, normalized, whole bool) int {
	if p.note || len(segs) == 0 {
		return -1
	}
	pat := p.segs
	if normalized {
		pat = p.nsegs
	}
	accept := uint64(1) << len(pat)
	states := closure(1, pat)
	for k := 1; k <= len(segs); k++ {
		if states = step(states, pat, segs[k-1]); states == 0 {
			return -1
		}
		if states&accept != 0 && (k < len(segs) || !p.dirOnly || whole) {
			return k
		}
	}
	return -1
}

// matchFile reports the matched prefix of an SBOM file path ("" if none).
func (p *pathPattern) matchFile(file string) string {
	segs := splitPath(file)
	if k := p.matchRoot(segs, false, false); k > 0 {
		return strings.Join(segs[:k], "/")
	}
	return ""
}

// matchPackage reports whether a package matches by name (anchored patterns
// never match a bare name) or by one of its source files.
func (p *pathPattern) matchPackage(name string, files []string) bool {
	if !p.anchored {
		var segs []string
		for _, s := range strings.Split(normName(name), "/") {
			if s != "" {
				segs = append(segs, s)
			}
		}
		if p.matchRoot(segs, true, true) > 0 {
			return true
		}
	}
	for _, f := range files {
		if p.matchFile(f) != "" {
			return true
		}
	}
	return false
}

// fileMatcher matches one pattern against many files, remembering the state
// after each directory, since the files of an image share directories.
type fileMatcher struct {
	p    *pathPattern
	dirs map[string]dirState
}

type dirState struct {
	states uint64
	root   string // the matched prefix of the directory, if any
}

func newFileMatcher(p *pathPattern) *fileMatcher {
	return &fileMatcher{p: p, dirs: map[string]dirState{}}
}

// match is matchFile for a clean path ("a/b/c", as cleanPath returns).
func (m *fileMatcher) match(name string) string {
	if m.p.note || name == "" {
		return ""
	}
	i := strings.LastIndexByte(name, '/')
	d := m.dir(name[:max(i, 0)])
	if d.root != "" {
		return d.root
	}
	if d.states == 0 || m.p.dirOnly {
		return ""
	}
	if step(d.states, m.p.segs, name[i+1:])&(1<<len(m.p.segs)) != 0 {
		return name
	}
	return ""
}

// dir returns the state after a clean directory path ("" is the root).
func (m *fileMatcher) dir(key string) dirState {
	if key == "" {
		return dirState{states: closure(1, m.p.segs)}
	}
	if d, ok := m.dirs[key]; ok {
		return d
	}
	i := strings.LastIndexByte(key, '/')
	d := m.dir(key[:max(i, 0)])
	if d.root == "" && d.states != 0 {
		d = dirState{states: step(d.states, m.p.segs, key[i+1:])}
		if d.states&(1<<len(m.p.segs)) != 0 {
			d.root = key
		}
	}
	m.dirs[key] = d
	return d
}

// sourcePaths extracts the absolute file paths syft lists in a package's
// sourceInfo ("acquired package info from <what>: /a/b, /c/d").
func sourcePaths(info string) []string {
	_, list, ok := strings.Cut(info, ": ")
	if !ok {
		return nil
	}
	var out []string
	for _, f := range strings.Split(list, ", ") {
		if f = strings.TrimSpace(f); strings.HasPrefix(f, "/") {
			out = append(out, f)
		}
	}
	return out
}
