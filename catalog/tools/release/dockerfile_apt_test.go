package main

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Reproducible image builds (D-028, pre-publish review item supply-4). build-image.sh rebuilds every image
// without cache and fails when the digest differs. SOURCE_DATE_EPOCH=0 with rewrite-timestamp fixes file
// times, not file contents, so no build step may leave a file whose contents carry the build time:
//
//   - apt, dpkg, update-alternatives and ldconfig write /var/log/dpkg.log, /var/log/apt/*,
//     /var/log/alternatives.log (a timestamp on every line) and /var/cache/ldconfig/aux-cache (inode and ctime
//     of every library), and leave the backups /var/cache/debconf/*-old and /var/lib/dpkg/*-old. Every RUN
//     that runs one of them, in a stage whose root filesystem reaches the image, must end with aptCleanup.
//   - pnpm writes node_modules/.modules.yaml (prunedAt) and node_modules/.pnpm-workspace-state*.json
//     (lastValidatedTimestamp) on every install and deploy. A node_modules tree that another stage copies (or
//     that stays in the image) must lose both after the last pnpm command that writes it.
//
// This test reads the Dockerfiles only. The real proof is images-pr.yml, which rebuilds every changed image
// without cache on pull requests, as images.yml does on main.

var aptCleanupPaths = []string{"/var/log/dpkg.log", "/var/log/apt", "/var/log/alternatives.log",
	"/var/cache/ldconfig/aux-cache", "/var/cache/debconf/*-old", "/var/lib/dpkg/*-old"}

var aptCleanup = "rm -rf " + strings.Join(aptCleanupPaths, " ")

var pnpmStampFiles = []string{"node_modules/.modules.yaml", "node_modules/.pnpm-workspace-state*.json"}

// aptTools write wall-clock logs or caches (dpkg-* covers dpkg-reconfigure, dpkg-divert and the others).
var aptTools = map[string]bool{"apt-get": true, "apt": true, "aptitude": true, "dpkg": true, "ldconfig": true,
	"update-alternatives": true}

// pnpmWriters are the pnpm subcommands that write a node_modules tree.
var pnpmWriters = map[string]bool{"install": true, "i": true, "add": true, "deploy": true, "update": true, "up": true,
	"upgrade": true, "remove": true, "rm": true, "uninstall": true, "un": true, "prune": true, "rebuild": true, "rb": true,
	"import": true, "install-test": true, "it": true}

// pnpmValueFlags take the next word as their value.
var pnpmValueFlags = map[string]bool{"--filter": true, "-F": true, "--filter-prod": true, "-C": true, "--dir": true,
	"--store-dir": true, "--workspace-dir": true, "--reporter": true, "--loglevel": true, "--config": true}

type dfInstr struct {
	line int    // first line of the instruction
	cmd  string // keyword, upper case
	args string // the rest, continuation lines joined and comment lines dropped (as BuildKit does)
}

// parseDockerfile splits a Dockerfile into instructions. Heredocs are refused, so a check never passes by
// not seeing a command.
func parseDockerfile(src string) ([]dfInstr, error) {
	var out []dfInstr
	var cur *dfInstr
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		cont := strings.HasSuffix(line, "\\")
		line = strings.TrimSuffix(line, "\\")
		if cur == nil {
			kw, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
			cur = &dfInstr{line: i + 1, cmd: strings.ToUpper(strings.TrimSpace(kw)), args: rest}
		} else {
			cur.args += line
		}
		if !cont {
			cur.args = strings.TrimSpace(cur.args)
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("line %d: the file ends inside a continuation", cur.line)
	}
	return out, nil
}

var heredocRe = regexp.MustCompile(`^(--\S+\s+)*<<-?\s*["']?[A-Za-z_]`)

// splitShell splits a shell script into simple commands (at ; & | newline and parentheses outside quotes and
// command substitutions) of unquoted words. Leading reserved words and variable assignments are dropped. It
// is not a shell parser, but it never splits inside quotes or $(...), which is what the checks need.
func splitShell(s string) [][]string {
	var cmds [][]string
	var words []string
	var w strings.Builder
	inWord := false
	var stack []byte // open contexts: ' and " and ` for quotes, ( for $( and for ( inside it
	flushWord := func() {
		if inWord {
			words = append(words, w.String())
			w.Reset()
			inWord = false
		}
	}
	flushCmd := func() {
		flushWord()
		for len(words) > 0 && (shellReserved[words[0]] || assignRe.MatchString(words[0])) {
			words = words[1:]
		}
		if len(words) > 0 && (words[0] == "env" || words[0] == "exec" || words[0] == "command") {
			words = words[1:]
			for len(words) > 0 && assignRe.MatchString(words[0]) {
				words = words[1:]
			}
		}
		if len(words) > 0 {
			cmds = append(cmds, words)
		}
		words = nil
	}
	pop := func(c byte) {
		stack = stack[:len(stack)-1]
		if len(stack) > 0 {
			w.WriteByte(c) // a nested closing quote or parenthesis stays in the word
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ctx := byte(0)
		if len(stack) > 0 {
			ctx = stack[len(stack)-1]
		}
		switch ctx {
		case '\'':
			if c == '\'' {
				pop(c)
			} else {
				w.WriteByte(c)
			}
		case '"', '`':
			switch {
			case c == '\\' && i+1 < len(s):
				if len(stack) > 1 {
					w.WriteByte(c)
				}
				i++
				w.WriteByte(s[i])
			case c == ctx:
				pop(c)
			case c == '$' && i+1 < len(s) && s[i+1] == '(' && ctx == '"':
				stack = append(stack, '(')
				w.WriteString("$(")
				i++
			default:
				w.WriteByte(c)
			}
		case '(': // inside $( ... ): kept verbatim in the word
			switch {
			case c == '\\' && i+1 < len(s):
				w.WriteByte(c)
				i++
				w.WriteByte(s[i])
			case c == '\'' || c == '"' || c == '`':
				w.WriteByte(c)
				stack = append(stack, c)
			case c == '(':
				w.WriteByte(c)
				stack = append(stack, c)
			case c == ')':
				w.WriteByte(c) // $( was written too
				stack = stack[:len(stack)-1]
			default:
				w.WriteByte(c)
			}
		default: // unquoted, top level
			switch {
			case c == '\\' && i+1 < len(s):
				i++
				w.WriteByte(s[i])
				inWord = true
			case c == '\'' || c == '"' || c == '`':
				stack = append(stack, c)
				inWord = true
			case c == '$' && i+1 < len(s) && s[i+1] == '(':
				stack = append(stack, '(')
				w.WriteString("$(")
				i++
				inWord = true
			case c == '#' && !inWord:
				for i+1 < len(s) && s[i+1] != '\n' {
					i++
				}
			case c == ' ' || c == '\t':
				flushWord()
			case c == '&' && ((i > 0 && (s[i-1] == '>' || s[i-1] == '<')) || (i+1 < len(s) && s[i+1] == '>')):
				w.WriteByte(c) // a redirection such as >&2 or &>file
				inWord = true
			case strings.IndexByte(";&|\n()", c) >= 0:
				flushCmd()
			default:
				w.WriteByte(c)
				inWord = true
			}
		}
	}
	flushCmd()
	return cmds
}

var (
	shellReserved = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true,
		"done": true, "while": true, "until": true, "!": true, "{": true, "}": true, "time": true}
	assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// dfShellCmd is one shell command of a RUN, with the directory it runs in.
type dfShellCmd struct {
	run   int // index of the RUN within its stage
	line  int // Dockerfile line of the RUN
	words []string
	cwd   string
}

type dfCopy struct {
	from int // stage index
	srcs []string
	line int
}

type dfStage struct {
	name    string
	line    int
	base    int // stage index of FROM <stage>, -1 for an image
	workdir string
	runs    [][]dfShellCmd
	copies  []dfCopy // COPY and ADD --from=<stage> in this stage
}

func resolvePath(cwd, p string) string {
	if p == "" {
		return cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(cwd, p)
	}
	return path.Clean(p)
}

// within reports whether p is root or below it.
func within(p, root string) bool {
	return root == "/" || p == root || strings.HasPrefix(p, root+"/")
}

// stampRemoved reports whether an rm of got satisfies the required removal of want. The stamp files are
// written as globs (node_modules/.pnpm-workspace-state*.json), so an rm of the required glob matches by
// equality, and an rm of a concrete file the glob names (node_modules/.pnpm-workspace-state-v1.json) matches
// by path.Match. That keeps the check from caring which spelling a Dockerfile picks for the same file.
func stampRemoved(want, got string) bool {
	if got == want {
		return true
	}
	if ok, err := path.Match(want, got); err == nil && ok {
		return true
	}
	return false
}

func parseStages(instrs []dfInstr) ([]dfStage, error) {
	var stages []dfStage
	byName := map[string]int{}
	for _, in := range instrs {
		if in.cmd == "FROM" {
			f := strings.Fields(in.args)
			for len(f) > 0 && strings.HasPrefix(f[0], "--") {
				f = f[1:]
			}
			if len(f) == 0 {
				return nil, fmt.Errorf("line %d: FROM without an image", in.line)
			}
			st := dfStage{line: in.line, base: -1, workdir: "/"}
			if b, ok := byName[strings.ToLower(f[0])]; ok {
				st.base, st.workdir = b, stages[b].workdir
			}
			if len(f) >= 3 && strings.EqualFold(f[1], "AS") {
				st.name = strings.ToLower(f[2])
				byName[st.name] = len(stages)
			}
			stages = append(stages, st)
			continue
		}
		if len(stages) == 0 {
			continue // ARG before the first FROM
		}
		st := &stages[len(stages)-1]
		switch in.cmd {
		case "WORKDIR":
			st.workdir = resolvePath(st.workdir, strings.TrimSpace(in.args))
		case "RUN":
			if heredocRe.MatchString(in.args) {
				return nil, fmt.Errorf("line %d: RUN with a heredoc; this check cannot read it", in.line)
			}
			script := in.args
			if strings.HasPrefix(script, "[") {
				var argv []string
				if err := json.Unmarshal([]byte(script), &argv); err != nil {
					return nil, fmt.Errorf("line %d: RUN exec form: %v", in.line, err)
				}
				if len(argv) == 3 && (argv[0] == "/bin/sh" || argv[0] == "sh" || argv[0] == "/bin/bash" || argv[0] == "bash") && argv[1] == "-c" {
					script = argv[2]
				} else {
					script = strings.Join(argv, " ")
				}
			} else {
				for strings.HasPrefix(script, "--") {
					_, script, _ = strings.Cut(script, " ")
					script = strings.TrimSpace(script)
				}
			}
			cwd := st.workdir
			var cmds []dfShellCmd
			for _, words := range splitShell(script) {
				cmds = append(cmds, dfShellCmd{run: len(st.runs), line: in.line, words: words, cwd: cwd})
				if words[0] == "cd" {
					dir := "/root"
					if len(words) > 1 {
						dir = words[1]
					}
					cwd = resolvePath(cwd, dir)
				}
			}
			st.runs = append(st.runs, cmds)
		case "COPY", "ADD":
			if heredocRe.MatchString(in.args) {
				return nil, fmt.Errorf("line %d: %s with a heredoc; this check cannot read it", in.line, in.cmd)
			}
			var words []string
			if strings.HasPrefix(in.args, "[") {
				if err := json.Unmarshal([]byte(in.args), &words); err != nil {
					return nil, fmt.Errorf("line %d: %s exec form: %v", in.line, in.cmd, err)
				}
			} else {
				words = strings.Fields(in.args)
			}
			from := ""
			var rest []string
			for _, wd := range words {
				if v, ok := strings.CutPrefix(wd, "--from="); ok {
					from = strings.ToLower(v)
				} else if !strings.HasPrefix(wd, "--") {
					rest = append(rest, wd)
				}
			}
			if from == "" || len(rest) < 2 {
				continue
			}
			idx, ok := byName[from]
			if !ok {
				n, err := strconv.Atoi(from)
				if err != nil || n < 0 || n >= len(stages)-1 {
					continue // an image, not a stage
				}
				idx = n
			}
			var srcs []string
			for _, src := range rest[:len(rest)-1] {
				srcs = append(srcs, resolvePath("/", src))
			}
			st.copies = append(st.copies, dfCopy{from: idx, srcs: srcs, line: in.line})
		}
	}
	if len(stages) == 0 {
		return nil, fmt.Errorf("no FROM")
	}
	return stages, nil
}

// rootfsStages marks the stages whose whole root filesystem (and so its /var) ends up in the image: the
// final stage, every stage a marked stage is FROM, and every stage copied from at / or at a directory holding
// one of the apt paths. Copies count whichever stage makes them, which errs on the strict side.
func rootfsStages(stages []dfStage) []bool {
	reach := make([]bool, len(stages))
	reach[len(stages)-1] = true
	for _, st := range stages {
		for _, c := range st.copies {
			for _, src := range c.srcs {
				for _, p := range aptCleanupPaths {
					if within(p, src) {
						reach[c.from] = true
					}
				}
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for i, st := range stages {
			if reach[i] && st.base >= 0 && !reach[st.base] {
				reach[st.base], changed = true, true
			}
		}
	}
	return reach
}

// isRecursiveForceRm returns the operands of an rm command and whether it removes recursively and by force.
func isRecursiveForceRm(words []string) ([]string, bool) {
	args, ok := isRm(words)
	if !ok {
		return nil, false
	}
	recursive, force := false, false
	for _, wd := range words[1:] {
		if wd == "--" {
			break
		}
		switch {
		case wd == "--recursive":
			recursive = true
		case wd == "--force":
			force = true
		case strings.HasPrefix(wd, "-") && !strings.HasPrefix(wd, "--"):
			recursive = recursive || strings.ContainsAny(wd, "rR")
			force = force || strings.Contains(wd, "f")
		}
	}
	return args, recursive && force
}

func runsAptTool(cmds []dfShellCmd) string {
	for _, c := range cmds {
		b := path.Base(c.words[0])
		if aptTools[b] || strings.HasPrefix(b, "dpkg-") {
			return b
		}
	}
	return ""
}

// pnpmTarget returns the directory whose node_modules a pnpm command writes, or "" for other commands.
func pnpmTarget(c dfShellCmd) string {
	w := c.words
	if path.Base(w[0]) == "corepack" && len(w) > 1 && w[1] == "pnpm" {
		w = w[1:]
	}
	if path.Base(w[0]) != "pnpm" {
		return ""
	}
	dir, sub, subAt := "", "", -1
	for i := 1; i < len(w); i++ {
		wd := w[i]
		if strings.HasPrefix(wd, "-") {
			if (wd == "-C" || wd == "--dir") && i+1 < len(w) {
				dir = w[i+1]
			} else if v, ok := strings.CutPrefix(wd, "--dir="); ok {
				dir = v
			}
			if pnpmValueFlags[wd] {
				i++
			}
			continue
		}
		sub, subAt = wd, i
		break
	}
	if !pnpmWriters[sub] {
		return ""
	}
	if sub == "deploy" {
		for i := len(w) - 1; i > subAt; i-- {
			if !strings.HasPrefix(w[i], "-") {
				return resolvePath(c.cwd, w[i])
			}
		}
		return ""
	}
	return resolvePath(c.cwd, dir)
}

type reproStats struct {
	aptRuns   int // RUNs that ran an apt tool in a stage whose filesystem reaches the image
	pnpmTrees int // node_modules trees that reach the image
}

// checkDockerfileReproducible returns one problem per RUN or copied tree that would leave build-time data.
func checkDockerfileReproducible(name, src string) ([]string, reproStats, error) {
	var stats reproStats
	instrs, err := parseDockerfile(src)
	if err != nil {
		return nil, stats, fmt.Errorf("%s: %w", name, err)
	}
	stages, err := parseStages(instrs)
	if err != nil {
		return nil, stats, fmt.Errorf("%s: %w", name, err)
	}
	var probs []string
	reach := rootfsStages(stages)
	for i, st := range stages {
		if !reach[i] {
			continue
		}
		for _, cmds := range st.runs {
			tool := runsAptTool(cmds)
			if tool == "" {
				continue
			}
			stats.aptRuns++
			last := cmds[len(cmds)-1]
			args, ok := isRecursiveForceRm(last.words)
			for _, p := range aptCleanupPaths {
				ok = ok && contains(args, p)
			}
			if !ok {
				probs = append(probs, fmt.Sprintf("%s:%d: RUN runs %s but does not end with `%s`", name, last.line, tool, aptCleanup))
			}
		}
	}

	for i, st := range stages {
		var all []dfShellCmd
		for _, cmds := range st.runs {
			all = append(all, cmds...)
		}
		lastWrite := map[string]int{} // node_modules parent dir -> index of the last pnpm command writing it
		var dirs []string
		for j, c := range all {
			if d := pnpmTarget(c); d != "" {
				if _, seen := lastWrite[d]; !seen {
					dirs = append(dirs, d)
				}
				lastWrite[d] = j
			}
		}
		for _, d := range dirs {
			nm := path.Join(d, "node_modules")
			out, line := reach[i], stages[i].line
			for _, other := range stages {
				for _, c := range other.copies {
					if c.from != i {
						continue
					}
					for _, s := range c.srcs {
						if within(nm, s) || within(s, nm) {
							out, line = true, c.line
						}
					}
				}
			}
			if !out {
				continue
			}
			stats.pnpmTrees++
			for _, f := range pnpmStampFiles {
				want := resolvePath(d, f)
				removed := false
				for _, c := range all[lastWrite[d]+1:] {
					if args, ok := isRm(c.words); ok {
						for _, a := range args {
							removed = removed || stampRemoved(want, resolvePath(c.cwd, a))
						}
					}
				}
				if !removed {
					stage := st.name
					if stage == "" {
						stage = strconv.Itoa(i)
					}
					probs = append(probs, fmt.Sprintf("%s:%d: %s from stage %s reaches the image, but no rm of %s follows the last pnpm command that writes it",
						name, line, nm, stage, want))
				}
			}
		}
	}
	return probs, stats, nil
}

// isRm returns the operands of an rm command (any flags).
func isRm(words []string) ([]string, bool) {
	if len(words) == 0 || path.Base(words[0]) != "rm" {
		return nil, false
	}
	var args []string
	flags := true
	for _, wd := range words[1:] {
		if flags && wd == "--" {
			flags = false
			continue
		}
		if flags && strings.HasPrefix(wd, "-") {
			continue
		}
		args = append(args, wd)
	}
	return args, true
}

// Every image that images.yml builds passes the check. The images the review named must be among them, so
// the test cannot pass by checking nothing.
func TestBuiltDockerfilesLeaveNoBuildTime(t *testing.T) {
	root := repoRoot(t)
	set, err := LoadImages(root)
	if err != nil {
		t.Fatal(err)
	}
	stats := map[string]reproStats{}
	for _, b := range set.Build {
		probs, st, err := checkDockerfileReproducible(b.Dockerfile, readFile(t, filepath.Join(root, b.Dockerfile)))
		if err != nil {
			t.Error(err)
			continue
		}
		for _, p := range probs {
			t.Error(p)
		}
		stats[b.Dockerfile] = st
	}
	for _, f := range []string{"runtime/agent/Dockerfile", "catalog/apps/internal-tools/images/tooljet-ce/Dockerfile",
		"catalog/apps/scraper/images/scraper-runner-playwright/Dockerfile", "catalog/apps/crm/images/espocrm/Dockerfile"} {
		if st, ok := stats[f]; !ok || st.aptRuns == 0 {
			t.Errorf("%s: no apt RUN was checked (%+v, built: %v)", f, st, ok)
		}
	}
	for _, f := range []string{"runtime/agent/Dockerfile", "catalog/apps/scraper/images/scraper-runner-playwright/Dockerfile",
		"runtime/mpp-payer/Dockerfile", "catalog/apps/inference-relay/images/relay/Dockerfile"} {
		if st, ok := stats[f]; !ok || st.pnpmTrees == 0 {
			t.Errorf("%s: no copied pnpm tree was checked (%+v, built: %v)", f, st, ok)
		}
	}
}

func TestDockerfileReproducibilityCheck(t *testing.T) {
	cleanup := aptCleanup
	pnpmRm := "rm -f /out/node_modules/.modules.yaml /out/node_modules/.pnpm-workspace-state*.json"
	cases := []struct {
		name string
		src  string
		want []string // one substring per expected problem
	}{
		{"sealed-agent before the fix", `FROM node AS build
WORKDIR /src
RUN corepack install && pnpm install --frozen-lockfile --filter "@sealed/agent..."
RUN pnpm --filter @sealed/core build \
 && pnpm --filter @sealed/agent deploy --prod --legacy /out
FROM node AS runtime
RUN printf '%s\n' "Types: deb" > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      mount=2.38.1-5+deb12u3 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 sealed
WORKDIR /app
COPY --from=build /out /app
`, []string{"Dockerfile:7: RUN runs apt-get", "/out/node_modules from stage build reaches the image, but no rm of /out/node_modules/.modules.yaml",
			"no rm of /out/node_modules/.pnpm-workspace-state*.json"}},
		{"sealed-agent after the fix", `FROM node AS build
WORKDIR /src
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @sealed/agent deploy --prod --legacy /out \
 && ` + pnpmRm + `
FROM node AS runtime
RUN apt-get update \
 && apt-get install -y mount \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system sealed \
 && ` + cleanup + `
COPY --from=build /out /app
`, nil},
		{"tooljet before the fix: ldconfig and a purge in a stage copied at /", `FROM tooljet AS upstream
RUN set -eux; \
    apt-get purge -y --auto-remove redis-server; \
    rm -rf /opt/oracle; \
    ldconfig; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /tmp/*; \
    if find / -xdev -name 'redis-server' -print | grep -q .; then \
      echo "forbidden binaries left in the image" >&2; exit 1; \
    fi
FROM scratch
COPY --from=upstream / /
`, []string{"RUN runs apt-get"}},
		{"ldconfig alone", "FROM debian\nRUN ldconfig\n", []string{"RUN runs ldconfig"}},
		{"crm before the fix: part of the cleanup, not at the end", `FROM debian AS fetch
RUN apt-get update; apt-get install -y curl; rm -rf /var/lib/apt/lists/*
FROM debian
RUN set -eux; \
    apt-get update; \
    apt-get install -y apache2 php8.4-cli; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/log/dpkg.log; \
    # Debian's default site is not used.
    rm -rf /var/www/html; \
    test "$(id -u www-data):$(id -g www-data)" = "33:33"
COPY --from=fetch /espocrm /var/www/html
`, []string{"Dockerfile:4: RUN runs apt-get"}},
		{"the cleanup must be the last command", "FROM debian\nRUN apt-get install -y x && " + cleanup + " && useradd y\n", []string{"RUN runs apt-get"}},
		{"the cleanup must name every path", "FROM debian\nRUN apt-get install -y x && rm -rf /var/log/dpkg.log /var/log/apt\n", []string{"RUN runs apt-get"}},
		{"the cleanup must be recursive and forced", "FROM debian\nRUN apt-get install -y x && rm " + strings.Join(aptCleanupPaths, " ") + "\n", []string{"RUN runs apt-get"}},
		{"a quoted cleanup is not a cleanup", "FROM debian\nRUN apt-get install -y x && echo \"" + cleanup + "\"\n", []string{"RUN runs apt-get"}},
		{"separators inside quotes and $( ) do not split", `FROM debian
RUN apt-get install -y x; \
    test -z "$(find / -name 'a;b' ! -exec grep -q 'x && y' {} \; -print)"; \
    bad="$(jq -r '.p[] | "\(.name) \(.license)"' /x.json)"; \
    ` + cleanup + `
`, nil},
		{"a fixed RUN", "FROM debian\nRUN apt-get install -y x && " + strings.Replace(cleanup, "rm -rf", "rm -fr", 1) + "\n", nil},
		{"a build stage copied in part is not checked", `FROM debian AS fetch
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
FROM scratch
COPY --from=fetch /espocrm /var/www/html
`, nil},
		{"the stage the final stage is FROM is checked", "FROM debian AS base\nRUN apt-get install -y x\nFROM base\nRUN true\n", []string{"Dockerfile:2: RUN runs apt-get"}},
		{"a stage copied at /var is checked", "FROM debian AS a\nRUN apt-get install -y x\nFROM scratch\nCOPY --from=a /var /var\n", []string{"RUN runs apt-get"}},
		{"a stage copied by index", "FROM node\nRUN pnpm deploy --prod /out\nFROM node\nCOPY --from=0 /out /app\n", []string{"no rm of /out/node_modules/.modules.yaml", "no rm of /out/node_modules/.pnpm-workspace-state*.json"}},
		{"scraper after the fix: cd /app and relative rm", `FROM pw AS build
WORKDIR /src/runner
RUN pnpm install --frozen-lockfile --ignore-workspace
RUN mkdir /app \
 && cd /app \
 && pnpm install --frozen-lockfile --ignore-workspace --prod \
 && rm -f node_modules/.modules.yaml node_modules/.pnpm-workspace-state*.json \
 && cp -r /src/runner/dist /app/dist
FROM pw AS rootfs
COPY --from=build /app /app
FROM scratch
COPY --from=rootfs / /
`, nil},
		{"scraper before the fix", `FROM pw AS build
WORKDIR /src/runner
RUN pnpm install --frozen-lockfile --ignore-workspace
RUN mkdir /app && cd /app && pnpm install --frozen-lockfile --ignore-workspace --prod && cp -r /src/runner/dist /app/dist
FROM pw AS rootfs
COPY --from=build /app /app
FROM scratch
COPY --from=rootfs / /
`, []string{"/app/node_modules from stage build", "/app/node_modules/.pnpm-workspace-state*.json"}},
		{"stamps removed before the last pnpm write", "FROM node AS build\nRUN pnpm deploy --prod /out && " + pnpmRm + " && pnpm --dir /out add left-pad\nFROM node\nCOPY --from=build /out /app\n",
			[]string{"no rm of /out/node_modules/.modules.yaml", "no rm of /out/node_modules/.pnpm-workspace-state*.json"}},
		{"only one stamp removed", "FROM node AS build\nRUN pnpm deploy --prod /out && rm -f /out/node_modules/.modules.yaml\nFROM node\nCOPY --from=build /out /app\n",
			[]string{"no rm of /out/node_modules/.pnpm-workspace-state*.json"}},
		{"a concrete workspace-state filename is accepted for the glob", "FROM node AS build\nRUN pnpm deploy --prod /out \\\n && rm -f /out/node_modules/.modules.yaml /out/node_modules/.pnpm-workspace-state-v1.json\nFROM node\nCOPY --from=build /out /app\n", nil},
		{"a pnpm tree that is not copied is not checked", "FROM node AS build\nWORKDIR /src\nRUN pnpm install && pnpm deploy --prod /out && " + pnpmRm + "\nFROM node\nCOPY --from=build /out /app\n", nil},
		{"pnpm in the final stage", "FROM node\nWORKDIR /app\nRUN pnpm install --prod\n", []string{"/app/node_modules from stage 0", "/app/node_modules/.pnpm-workspace-state*.json"}},
		{"pnpm run is not a write", "FROM node AS build\nWORKDIR /out\nRUN pnpm run build\nFROM node\nCOPY --from=build /out /app\n", nil},
	}
	for _, c := range cases {
		probs, _, err := checkDockerfileReproducible("Dockerfile", c.src)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		joined := strings.Join(probs, "\n")
		if len(probs) != len(c.want) {
			t.Errorf("%s: %d problems, want %d:\n%s", c.name, len(probs), len(c.want), joined)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(joined, w) {
				t.Errorf("%s: want %q in:\n%s", c.name, w, joined)
			}
		}
	}
	if _, _, err := checkDockerfileReproducible("Dockerfile", "FROM debian\nRUN <<EOF\napt-get install -y x\nEOF\n"); err == nil || !strings.Contains(err.Error(), "heredoc") {
		t.Errorf("a heredoc RUN must be refused, got %v", err)
	}
}

func TestSplitShell(t *testing.T) {
	got := splitShell(`set -eux; if [ -n "$X" ]; then FOO=1 env BAR=2 apt-get install -y 'a b'; fi && cd /app || echo "x; y" | tee $(echo "z" | cut -c1) # rm -rf /`)
	want := [][]string{{"set", "-eux"}, {"[", "-n", "$X", "]"}, {"apt-get", "install", "-y", "a b"}, {"cd", "/app"},
		{"echo", "x; y"}, {"tee", `$(echo "z" | cut -c1)`}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("splitShell\n got %q\nwant %q", got, want)
	}
}
