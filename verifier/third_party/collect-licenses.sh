#!/bin/sh
# Copies the license, notice, patents and authors files of every Go module
# linked into one binary, and those of the Go distribution (the standard
# library is linked in too), into OUTDIR/<module path>/, and writes
# OUTDIR/README: what is linked, the GNU LGPL notice for LGPL modules
# (go-ethereum) and where the corresponding source is.
#
# Usage, from the repository root (the directory holding go.mod):
#   SOURCE_URL=https://github.com/<owner>/<repo> [SOURCE_REF=<commit or tag>] \
#     sh <component>/third_party/collect-licenses.sh OUTDIR PACKAGE
# GOOS, GOARCH, CGO_ENABLED and GOFLAGS are honored, so the module set
# matches the build; BUILD_TAGS (comma separated) is passed as -tags.
# DOCKERFILE, if set, is named in the README as the image recipe.
#
# It fails when a linked module has no license text (a LICENSE, LICENCE,
# COPYING or COPYRIGHT file) at its root, when a linked module or package is
# under the GPL or AGPL without the LGPL (that needs a recorded decision
# first), and when an LGPL-3.0 module does not ship the GPL-3.0 text the
# LGPL supplements.
#
# This is runtime/egress/build/collect-licenses.sh with the package as an
# argument, plus: license files that linked packages carry in their own
# directories (go-ethereum/metrics/LICENSE from rcrowley/go-metrics,
# go-ethereum/crypto/keccak/LICENSE), AUTHORS files, the main module's
# LICENSE and the README. verifier/third_party and key-broker/third_party
# hold identical copies.
set -eu

usage='usage: collect-licenses.sh OUTDIR PACKAGE'
out=${1:?$usage}
pkg=${2:?$usage}
tags=${BUILD_TAGS:-}
source_url=${SOURCE_URL:?SOURCE_URL must name the public source repository}
source_ref=${SOURCE_REF:-}

tab=$(printf '\t')
# Case-insensitive file name patterns: license texts, and the other files a
# notice or license refers to.
text_re='^((un)?licen[cs]e|copying|copyright)([._-].*)?$'
other_re='^(notice|patents|authors)([._-].*)?$'

die() {
	echo "collect-licenses: $*" >&2
	exit 1
}

# matching DIR REGEX: regular files in DIR whose names match REGEX (Go
# sources excluded), one name per line, sorted.
matching() {
	for f in "$1"/*; do
		if [ -f "$f" ]; then printf '%s\n' "${f##*/}"; fi
	done | grep -i -E "$2" | grep -v -i '\.go$' | LC_ALL=C sort
}

# kind FILE: lgpl, gpl or other, from the license text.
kind() {
	if grep -q 'GNU LESSER GENERAL PUBLIC LICENSE' "$1"; then
		echo lgpl
	elif grep -q -E 'GNU (AFFERO )?GENERAL PUBLIC LICENSE' "$1"; then
		echo gpl
	else
		echo other
	fi
}

# escape S: module path or version escaped for the module proxy protocol.
escape() {
	printf '%s\n' "$1" | awk '{
		s = ""
		for (i = 1; i <= length($0); i++) {
			c = substr($0, i, 1)
			if (c ~ /[A-Z]/) s = s "!" tolower(c); else s = s c
		}
		print s
	}'
}

work=$(mktemp -d "${TMPDIR:-/tmp}/collect-licenses.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' INT TERM
mkdir -p "$out"

# One line per linked package outside the main module: module path, version,
# replacement (path@version, - for none), module dir, package dir.
go list -deps -tags "$tags" -f '{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{or .Version "-"}}{{"\t"}}{{with .Replace}}{{.Path}}@{{or .Version "-"}}{{else}}-{{end}}{{"\t"}}{{.Dir}}{{"\t"}}{{$.Dir}}{{end}}{{end}}' "$pkg" >"$work/list" ||
	die "go list failed for $pkg"
grep -v '^$' "$work/list" >"$work/pkgs" || true
cut -f1-4 "$work/pkgs" | LC_ALL=C sort -u >"$work/mods"
[ -s "$work/mods" ] || die "go list found no linked modules for $pkg"
: >"$work/lgpl"

# Module roots.
while IFS="$tab" read -r path ver repl mdir; do
	[ -n "$mdir" ] && [ -d "$mdir" ] || die "$path $ver is not in the module cache (run go mod download)"
	matching "$mdir" "$text_re" >"$work/texts"
	[ -s "$work/texts" ] || die "no license text (LICENSE, LICENCE, COPYING, COPYRIGHT) in $mdir ($path $ver)"
	matching "$mdir" "$other_re" >"$work/others"
	mkdir -p "$out/$path"
	lgpl="" lgpl3=0 gpl="" gpl3=0
	while IFS= read -r n; do
		cp -f "$mdir/$n" "$out/$path/$n"
		k=$(kind "$mdir/$n")
		[ "$k" != other ] || continue
		v=$(sed -n 's/^[[:space:]]*Version \([0-9.]*\),.*/\1/p' "$mdir/$n" | head -n 1)
		if [ "$k" = lgpl ]; then
			lgpl="$lgpl${lgpl:+, }GNU LGPL version ${v:-unknown} ($n)"
			if [ "$v" = 3 ]; then lgpl3=1; fi
		else
			gpl="$gpl${gpl:+, }GNU GPL version ${v:-unknown} ($n)"
			if [ "$v" = 3 ]; then gpl3=1; fi
		fi
	done <"$work/texts"
	while IFS= read -r n; do
		cp -f "$mdir/$n" "$out/$path/$n"
	done <"$work/others"
	if [ -n "$lgpl" ]; then
		if [ "$lgpl3" = 1 ] && [ "$gpl3" != 1 ]; then
			die "$path $ver is under LGPL-3.0 but ships no GPL-3.0 text (LGPL-3.0 section 4(b) needs both)"
		fi
		printf '%s\t%s\t%s\t%s\n' "$path" "$ver" "$repl" "$lgpl${gpl:+ with the }$gpl" >>"$work/lgpl"
	elif [ -n "$gpl" ]; then
		die "$path $ver is under the GPL or AGPL; linking it needs a recorded decision"
	fi
done <"$work/mods"

# Package directories below a module root that carry their own files.
while IFS="$tab" read -r path ver repl mdir pdir; do
	d=$pdir
	while [ "$d" != "$mdir" ] && [ "${d#"$mdir"/}" != "$d" ]; do
		printf '%s\t%s\t%s\n' "$path" "$mdir" "${d#"$mdir"/}"
		d=${d%/*}
	done
done <"$work/pkgs" | LC_ALL=C sort -u >"$work/dirs"
while IFS="$tab" read -r path mdir rel; do
	{
		matching "$mdir/$rel" "$text_re"
		matching "$mdir/$rel" "$other_re"
	} >"$work/files"
	[ -s "$work/files" ] || continue
	mkdir -p "$out/$path/$rel"
	while IFS= read -r n; do
		cp -f "$mdir/$rel/$n" "$out/$path/$rel/$n"
		# A copyleft text below the root of a module whose root is not LGPL is
		# an unusual layout: stop so that someone reviews it.
		if [ "$(kind "$mdir/$rel/$n")" != other ] && ! cut -f1 "$work/lgpl" | grep -q -x -F "$path"; then
			die "$path/$rel/$n is a GNU GPL, LGPL or AGPL text in a module that is not LGPL; review it before linking"
		fi
	done <"$work/files"
done <"$work/dirs"

# The main module (this repository).
main_path=$(go list -m -f '{{.Path}}')
main_dir=$(go list -m -f '{{.Dir}}')
matching "$main_dir" "$text_re" >"$work/texts"
[ -s "$work/texts" ] || die "no LICENSE in $main_dir ($main_path)"
mkdir -p "$out/$main_path"
while IFS= read -r n; do
	cp -f "$main_dir/$n" "$out/$main_path/$n"
done <"$work/texts"

# The golang image keeps LICENSE in GOROOT; Homebrew keeps it one level up.
goroot=$(go env GOROOT)
mkdir -p "$out/go"
for d in "$goroot" "$goroot/.."; do
	if [ -f "$d/LICENSE" ]; then
		cp -f "$d/LICENSE" "$out/go/"
		break
	fi
done
[ -f "$out/go/LICENSE" ] || die "Go distribution LICENSE not found near $goroot"
if [ -f "$goroot/PATENTS" ]; then
	cp -f "$goroot/PATENTS" "$out/go/"
fi

# README.
bin=${pkg##*/}
[ "$bin" != . ] || bin=${main_path##*/}
target="CGO_ENABLED=$(go env CGO_ENABLED) GOOS=$(go env GOOS) GOARCH=$(go env GOARCH)"
if [ -n "$tags" ]; then tagflag=" -tags $tags"; else tagflag=""; fi
if [ -n "$source_ref" ]; then
	app_src="$source_url/tree/$source_ref"
else
	app_src="$source_url at the commit this image was built from (the release that publishes the image names it)"
fi
{
	cat <<END
Licenses of the software in this image

Program: $bin
Built from: the Go package $pkg of the module $main_path
Source: $source_url
License of the program's own code: Apache License 2.0 (in $main_path/)
Target: $target, $(go env GOVERSION)

$bin statically links the Go standard library and the Go modules listed
below. go/ holds the Go distribution's LICENSE and PATENTS. The directory
of each module holds the license, notice, patents and authors files that
ship with that version, and a subdirectory holds the files that a linked
package carries in its own directory.

Linked modules:
END
	while IFS="$tab" read -r path ver repl mdir; do
		if [ "$repl" = "-" ]; then
			echo "  $path $ver"
		elif [ "${repl##*@}" = "-" ]; then
			echo "  $path $ver => ${repl%@*}"
		else
			echo "  $path $ver => ${repl%@*} ${repl##*@}"
		fi
	done <"$work/mods"
	if [ -s "$work/lgpl" ]; then
		cat <<END

GNU Lesser General Public License notice (LGPL-3.0 section 4)

$bin uses the libraries below, which are covered by the GNU Lesser General
Public License. Each library and its use in $bin are covered by that
license. Its text, and the text of the GNU General Public License that it
supplements, are in the directory named.

END
		while IFS="$tab" read -r path ver repl files; do
			echo "  $path $ver: $files, in $path/"
		done <"$work/lgpl"
		cat <<END

Corresponding source (LGPL-3.0 section 4(d)(0), GPL-3.0 section 6(d)):

- Application code: $app_src.
  Its go.mod and go.sum pin every module listed above by version and hash.
- Library source, the exact version linked, from the Go module proxy
  (go.sum records each archive's hash):
END
		while IFS="$tab" read -r path ver repl files; do
			if [ "$repl" = "-" ]; then
				p=$path v=$ver
			else
				p=${repl%@*} v=${repl##*@}
			fi
			if [ "$v" = "-" ]; then
				echo "  $path: the directory $p in the application code"
			else
				echo "  $path: https://proxy.golang.org/$(escape "$p")/@v/$(escape "$v").zip"
			fi
		done <"$work/lgpl"
		cat <<END
- To relink $bin with a modified version of a library: check out the
  application code, point it at your copy with
    go mod edit -replace <module path>=<directory of your copy>
  and build with
    $target go build -trimpath$tagflag $pkg
END
		if [ -n "${DOCKERFILE:-}" ]; then
			echo "  $DOCKERFILE in the application code builds this image the same way."
		fi
	fi
} >"$out/README"
