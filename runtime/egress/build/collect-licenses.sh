#!/bin/sh
# Copies the license and notice files of every module linked into
# sealed-egress, and of the Go distribution (the standard library is linked
# in too), into OUTDIR/<module path>/. MIT and BSD require the notice in
# binary redistributions; Apache-2.0 requires the license text and NOTICE.
#
# Usage, from the repository root (the directory holding go.mod):
#   runtime/egress/build/collect-licenses.sh OUTDIR
# GOOS, GOARCH and GOFLAGS are honored, so the module set matches the build.
set -eu

out=${1:?usage: collect-licenses.sh OUTDIR}
pkg=./runtime/egress/cmd/sealed-egress
tags=smokescreen_no_prometheus

mkdir -p "$out"
go list -deps -tags "$tags" \
	-f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Dir}}{{end}}{{end}}' "$pkg" |
	sort -u |
	while read -r path dir; do
		[ -n "$path" ] || continue
		found=0
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS*; do
			[ -f "$f" ] || continue
			mkdir -p "$out/$path"
			cp "$f" "$out/$path/"
			found=1
		done
		if [ "$found" -ne 1 ]; then
			echo "collect-licenses: no license file in $dir ($path)" >&2
			exit 1
		fi
	done

# The golang image keeps LICENSE in GOROOT; Homebrew keeps it one level up.
goroot=$(go env GOROOT)
mkdir -p "$out/go"
for d in "$goroot" "$goroot/.."; do
	if [ -f "$d/LICENSE" ]; then
		cp "$d/LICENSE" "$out/go/"
		break
	fi
done
if [ ! -f "$out/go/LICENSE" ]; then
	echo "collect-licenses: Go distribution LICENSE not found near $goroot" >&2
	exit 1
fi
if [ -f "$goroot/PATENTS" ]; then
	cp "$goroot/PATENTS" "$out/go/"
fi
