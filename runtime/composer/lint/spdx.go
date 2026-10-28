package lint

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// LicenseStatus orders outcomes from best to worst.
type LicenseStatus int

const (
	// Allowed: on the rule 9 list or the D-021 additions.
	Allowed LicenseStatus = iota
	// SystemOnly: acceptable only for OS distribution packages in base
	// images (D-021), for example GPL-2.0-only.
	SystemOnly
	// Unknown: not recognized; needs a human decision.
	Unknown
	// Banned: hard fail (SSPL, BUSL, FSL, Elastic, Sustainable Use, Commons
	// Clause, RSAL, proprietary).
	Banned
)

func (s LicenseStatus) String() string {
	return [...]string{"allowed", "system-only", "unknown", "banned"}[s]
}

// LicenseResult is the evaluation of an SPDX license expression.
type LicenseResult struct {
	Expr   string
	Status LicenseStatus
	// Elected is the license (or AND-combination) a disjunction is used
	// under, when the expression has OR choices.
	Elected string
	// Banned lists banned identifiers that appear anywhere, even in an
	// alternative that is not elected.
	Banned []string
}

// allowedLicenses is rule 9 (MIT, Apache-2.0, BSD-2/3-Clause, ISC, MPL-2.0,
// LGPL, GPL-3.0, AGPL-3.0) plus the D-021 additions. GPL-2.0-or-later is
// allowed because it can be used under GPL-3.0.
var allowedLicenses = set(
	"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
	"LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
	"GPL-3.0-only", "GPL-3.0-or-later", "GPL-2.0-or-later",
	"AGPL-3.0-only", "AGPL-3.0-or-later",
	"PostgreSQL", "Zlib", "0BSD", "Unlicense", "CC0-1.0", "PSF-2.0", "Python-2.0", "BSL-1.0",
)

// systemLicenses are OSI-approved licenses common in Debian, Alpine and
// Ubuntu base images that are not on the allowlist for app code.
var systemLicenses = set(
	"GPL-2.0-only", "GPL-1.0-or-later", "Artistic-1.0-Perl", "Artistic-2.0", "MPL-1.1", "EPL-1.0", "EPL-2.0",
	"Apache-1.1", "OFL-1.1", "NCSA", "Unicode-DFS-2016", "Unicode-3.0", "BSD-1-Clause", "ZPL-2.1", "OLDAP-2.8",
	"MIT-0", "X11", "BSD-4-Clause", "OpenSSL", "curl", "IJG", "Libpng", "libtiff", "FTL", "bzip2-1.0.6",
	"GFDL-1.2-or-later", "GFDL-1.3-or-later", "Sleepycat", "W3C", "HPND", "ICU", "PHP-3.01", "Ruby", "Vim",
)

// bannedLicenses are exact SPDX identifiers that always fail.
var bannedLicenses = set(
	"SSPL-1.0", "BUSL-1.1", "Elastic-2.0", "FSL-1.0-MIT", "FSL-1.0-Apache-2.0", "FSL-1.1-MIT",
	"FSL-1.1-Apache-2.0", "FSL-1.1-ALv2", "Commons-Clause", "SUL-1.0",
)

// bannedFragments match LicenseRef-* and other free-form identifiers
// (case-insensitive substrings).
var bannedFragments = []string{
	"sspl", "busl", "bsl-1.1", "business-source", "elastic", "fsl-1", "functional-source", "sustainable-use",
	"commons-clause", "rsal", "redis-source-available", "proprietary", "commercial", "enterprise", "confluent-community",
}

// deprecatedAliases maps deprecated SPDX ids to current ones.
var deprecatedAliases = map[string]string{
	"GPL-2.0": "GPL-2.0-only", "GPL-2.0+": "GPL-2.0-or-later", "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later",
	"LGPL-2.0": "LGPL-2.0-only", "LGPL-2.0+": "LGPL-2.0-or-later", "LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later",
	"LGPL-3.0": "LGPL-3.0-only", "LGPL-3.0+": "LGPL-3.0-or-later", "AGPL-3.0": "AGPL-3.0-only", "AGPL-3.0+": "AGPL-3.0-or-later",
	"GPL-1.0+": "GPL-1.0-or-later",
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// EvaluateLicense parses an SPDX expression (OR, AND, WITH, parentheses,
// "+") and classifies it. OR takes the best alternative, AND the worst.
func EvaluateLicense(expr string) LicenseResult {
	res := LicenseResult{Expr: expr}
	toks, err := tokenize(expr)
	if err != nil || len(toks) == 0 {
		res.Status = Unknown
		return res
	}
	p := &spdxParser{toks: toks}
	n, err := p.expr()
	if err != nil || p.pos != len(p.toks) {
		res.Status = Unknown
		return res
	}
	res.Status, res.Elected = n.eval()
	banned := map[string]bool{}
	n.collectBanned(banned)
	for b := range banned {
		res.Banned = append(res.Banned, b)
	}
	sort.Strings(res.Banned)
	return res
}

type spdxNode struct {
	op        string // "", "AND", "OR"
	id        string // leaf license id (normalized)
	exception string
	kids      []*spdxNode
}

func (n *spdxNode) eval() (LicenseStatus, string) {
	switch n.op {
	case "":
		return classify(n.id, n.exception), n.String()
	case "AND":
		worst, parts := Allowed, []string{}
		for _, k := range n.kids {
			s, e := k.eval()
			if s > worst {
				worst = s
			}
			parts = append(parts, e)
		}
		return worst, strings.Join(parts, " AND ")
	default: // OR
		best, elected := Banned, ""
		for i, k := range n.kids {
			s, e := k.eval()
			if i == 0 || s < best {
				best, elected = s, e
			}
		}
		return best, elected
	}
}

func (n *spdxNode) collectBanned(out map[string]bool) {
	if n.op == "" {
		if classify(n.id, n.exception) == Banned {
			out[n.String()] = true
		}
		return
	}
	for _, k := range n.kids {
		k.collectBanned(out)
	}
}

func (n *spdxNode) String() string {
	if n.op == "" {
		if n.exception != "" {
			return n.id + " WITH " + n.exception
		}
		return n.id
	}
	parts := make([]string, len(n.kids))
	for i, k := range n.kids {
		parts[i] = k.String()
		if k.op != "" {
			parts[i] = "(" + parts[i] + ")"
		}
	}
	return strings.Join(parts, " "+n.op+" ")
}

func classify(id, exception string) LicenseStatus {
	if isBanned(id) || (exception != "" && isBanned(exception)) {
		return Banned
	}
	switch {
	case allowedLicenses[id]:
		return Allowed
	case systemLicenses[id]:
		return SystemOnly
	}
	return Unknown
}

func isBanned(id string) bool {
	if bannedLicenses[id] {
		return true
	}
	lower := strings.ToLower(id)
	for _, f := range bannedFragments {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

// normalizeID maps deprecated ids to current ones. "X+" means "X or any
// later version": GPL-family ids become -or-later, anything else can be
// used under X itself.
func normalizeID(id string) string {
	if a, ok := deprecatedAliases[id]; ok {
		return a
	}
	if base, ok := strings.CutSuffix(id, "+"); ok {
		if a, ok := deprecatedAliases[base]; ok {
			return strings.TrimSuffix(a, "-only") + "-or-later"
		}
		return base
	}
	return id
}

func tokenize(s string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(s) {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(s) && !unicode.IsSpace(rune(s[j])) && s[j] != '(' && s[j] != ')' {
				ch := s[j]
				if !(ch == '-' || ch == '.' || ch == '+' || ch == ':' || ch == '_' ||
					(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
					return nil, fmt.Errorf("invalid character %q", ch)
				}
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks, nil
}

type spdxParser struct {
	toks []string
	pos  int
}

func (p *spdxParser) peekOp(op string) bool {
	return p.pos < len(p.toks) && strings.EqualFold(p.toks[p.pos], op)
}

func (p *spdxParser) expr() (*spdxNode, error) {
	return p.binary("OR", p.and)
}

func (p *spdxParser) and() (*spdxNode, error) {
	return p.binary("AND", p.with)
}

func (p *spdxParser) binary(op string, next func() (*spdxNode, error)) (*spdxNode, error) {
	first, err := next()
	if err != nil {
		return nil, err
	}
	kids := []*spdxNode{first}
	for p.peekOp(op) {
		p.pos++
		k, err := next()
		if err != nil {
			return nil, err
		}
		kids = append(kids, k)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &spdxNode{op: op, kids: kids}, nil
}

func (p *spdxParser) with() (*spdxNode, error) {
	n, err := p.atom()
	if err != nil {
		return nil, err
	}
	if p.peekOp("WITH") {
		if n.op != "" {
			return nil, fmt.Errorf("WITH applies to a single license")
		}
		p.pos++
		if p.pos >= len(p.toks) || isOperator(p.toks[p.pos]) {
			return nil, fmt.Errorf("missing exception after WITH")
		}
		n.exception = p.toks[p.pos]
		p.pos++
	}
	return n, nil
}

func (p *spdxParser) atom() (*spdxNode, error) {
	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("unexpected end")
	}
	t := p.toks[p.pos]
	if t == "(" {
		p.pos++
		n, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos] != ")" {
			return nil, fmt.Errorf("missing )")
		}
		p.pos++
		return n, nil
	}
	if t == ")" || isOperator(t) {
		return nil, fmt.Errorf("unexpected %q", t)
	}
	p.pos++
	return &spdxNode{id: normalizeID(t)}, nil
}

func isOperator(t string) bool {
	return strings.EqualFold(t, "AND") || strings.EqualFold(t, "OR") || strings.EqualFold(t, "WITH")
}
