#!/bin/sh

# This comment is used to simplify checking local copies of the script.  Bump
# this number every time a significant change is made to this script.
#
# AdGuard-Project-Version: 5

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '0' ]
then
	set -x
fi

# Set $EXIT_ON_ERROR to zero to see all errors.
if [ "${EXIT_ON_ERROR:-1}" -eq '0' ]
then
	set +e
else
	set -e
fi

set -f -u



# Source the common helpers, including not_found and run_linter.
. ./scripts/make/helper.sh



# Warnings

go_version="$( "${GO:-go}" version )"
readonly go_version

go_min_version='go1.20.7'
go_version_msg="
warning: your go version (${go_version}) is different from the recommended minimal one (${go_min_version}).
if you have the version installed, please set the GO environment variable.
for example:

	export GO='${go_min_version}'
"
readonly go_min_version go_version_msg

case "$go_version"
in
('go version'*"$go_min_version"*)
	# Go on.
	;;
(*)
	echo "$go_version_msg" 1>&2
	;;
esac



# Simple analyzers

# blocklist_imports is a simple check against unwanted packages.  The following
# packages are banned:
#
#   *  Packages errors and log are replaced by our own packages in the
#      github.com/AdguardTeam/golibs module.
#
#   *  Package io/ioutil is soft-deprecated.
#
#   *  Package reflect is often an overkill, and for deep comparisons there are
#      much better functions in module github.com/google/go-cmp.  Which is
#      already our indirect dependency and which may or may not enter the stdlib
#      at some point.
#
#      See https://github.com/golang/go/issues/45200.
#
#   *  Package sort is replaced by golang.org/x/exp/slices.
#
#   *  Package unsafe is… unsafe.
#
#   *  Package golang.org/x/net/context has been moved into stdlib.
#
# Currently, the only standard exception are files generated from protobuf
# schemas, which use package reflect.  If your project needs more exceptions,
# add and document them.
#
# NOTE: For AdGuard DNS, there are the following exceptions:
#
#   *  internal/profiledb/internal/filecachepb/unsafe.go: a “safe” unsafe helper
#      to prevent excessive allocations.
#
# TODO(a.garipov): Add deprecated packages golang.org/x/exp/maps and
# golang.org/x/exp/slices once all projects switch to Go 1.21.
blocklist_imports() {
	git grep\
		-e '[[:space:]]"errors"$'\
		-e '[[:space:]]"io/ioutil"$'\
		-e '[[:space:]]"log"$'\
		-e '[[:space:]]"reflect"$'\
		-e '[[:space:]]"sort"$'\
		-e '[[:space:]]"unsafe"$'\
		-e '[[:space:]]"golang.org/x/net/context"$'\
		-n\
		-- '*.go'\
		':!*.pb.go'\
		':!internal/profiledb/internal/filecachepb/unsafe.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 blocked import:\2/'\
		|| exit 0
}

# method_const is a simple check against the usage of some raw strings and
# numbers where one should use named constants.
method_const() {
	git grep -F\
		-e '"DELETE"'\
		-e '"GET"'\
		-e '"PATCH"'\
		-e '"POST"'\
		-e '"PUT"'\
		-n\
		-- '*.go'\
		| sed -e 's/^\([^[:space:]]\+\)\(.*\)$/\1 http method literal:\2/'\
		|| exit 0
}

# underscores is a simple check against Go filenames with underscores.  Add new
# build tags and OS as you go.  The main goal of this check is to discourage the
# use of filenames like client_manager.go.
underscores() {
	underscore_files="$(
		git ls-files '*_*.go'\
			| grep -F\
			-e '_generate.go'\
			-e '_grpc.pb.go'\
			-e '_linux.go'\
			-e '_noreuseport.go'\
			-e '_others.go'\
			-e '_reuseport.go'\
			-e '_test.go'\
			-e '_unix.go'\
			-e '_windows.go'\
			-v\
			| sed -e 's/./\t\0/'
	)"
	readonly underscore_files

	if [ "$underscore_files" != '' ]
	then
		echo 'found file names with underscores:'
		echo "$underscore_files"
	fi
}

# TODO(a.garipov): Add an analyzer to look for `fallthrough`, `goto`, and `new`?



# Checks

# TODO(a.garipov): Remove the dnsserver stuff once it is separated.
dnssrvmod='github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/...'
readonly dnssrvmod

run_linter -e blocklist_imports

run_linter -e method_const

run_linter -e underscores

run_linter -e gofumpt --extra -e -l .

# TODO(a.garipov): golint is deprecated, find a suitable replacement.

run_linter "$GO" vet ./... "$dnssrvmod"

run_linter govulncheck ./... "$dnssrvmod"

# NOTE: For AdGuard DNS, ignore the generated protobuf file.
run_linter gocyclo --ignore '\.pb\.go$' --over 10 .

# TODO(a.garipov): Enable 10 for all.
#
# TODO(a.garipov): Redo once https://github.com/uudashr/gocognit/issues/22 is
# fixed.
gocognit_paths="\
./internal/metrics 19
./internal/filter/internal/composite/ 15
./internal/ecscache 15
./internal/backend/   14
./internal/dnsserver/ 14
./internal/dnsmsg/            11
./internal/filter/hashprefix/ 11
./internal/agd/                              10
./internal/agdhttp/                          10
./internal/agdio/                            10
./internal/agdnet/                           10
./internal/agdprotobuf/                      10
./internal/agdtest/                          10
./internal/agdtime/                          10
./internal/billstat/                         10
./internal/bindtodevice/                     10
./internal/cmd/                              10
./internal/connlimiter/                      10
./internal/consul/                           10
./internal/debugsvc/                         10
./internal/dnscheck/                         10
./internal/dnsdb/                            10
./internal/dnsserver/cache/                  10
./internal/dnsserver/dnsservertest/          10
./internal/dnsserver/forward/                10
./internal/dnsserver/netext/                 10
./internal/dnsserver/pool/                   10
./internal/dnsserver/prometheus/             10
./internal/dnsserver/querylog/               10
./internal/dnsserver/ratelimit/              10
./internal/dnssvc/                           10
./internal/errcoll/                          10
./internal/filter/internal/custom/           10
./internal/filter/internal/filtertest/       10
./internal/filter/internal/resultcache/      10
./internal/filter/internal/rulelist/         10
./internal/filter/internal/safesearch/       10
./internal/filter/internal/serviceblock/     10
./internal/geoip/                            10
./internal/optlog/                           10
./internal/profiledb/internal/profiledbtest/ 10
./internal/querylog/                         10
./internal/rulestat/                         10
./internal/tools/                            10
./internal/websvc/                           10"
readonly gocognit_paths

echo "$gocognit_paths" | while read -r path max
do
	run_linter gocognit --over="$max" "$path"
done

run_linter ineffassign ./... "$dnssrvmod"

run_linter unparam ./... "$dnssrvmod"

git ls-files -- 'Makefile' '*.conf' '*.go' '*.mod' '*.sh' '*.yaml' '*.yml'\
	| xargs misspell --error\
	| sed -e 's/^/misspell: /'

run_linter looppointer ./... "$dnssrvmod"

run_linter nilness ./... "$dnssrvmod"

# Do not use fieldalignment on $dnssrvmod, because ameshkov likes to place
# struct fields in an order that he considers more readable.
#
# TODO(a.garipov): Remove the loop once golang/go#60509, golang/go#61574 are
# fixed.
(
	run_linter fieldalignment ./main.go
	run_linter -e shadow --strict ./main.go

	set +f
	for d in ./internal/*/ ./internal/*/*/ ./internal/*/*/*/
	do
		case "$d"
		in
		(*/testdata/*|\
			./internal/dnsserver/*|\
			./internal/backendpb/|\
			./internal/profiledb/internal/filecachepb/|\
			./internal/tools/)
			continue
			;;
		(*)
			run_linter fieldalignment "$d"
			run_linter -e shadow --strict "$d"
			;;
		esac
	done
)

run_linter -e shadow --strict "$dnssrvmod"

run_linter gosec --quiet ./... "$dnssrvmod"

run_linter errcheck ./... "$dnssrvmod"

staticcheck_matrix='
darwin: GOOS=darwin
linux:  GOOS=linux
'
readonly staticcheck_matrix

echo "$staticcheck_matrix" | run_linter staticcheck --matrix ./... "$dnssrvmod"
