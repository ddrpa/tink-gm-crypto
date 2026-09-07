#!/usr/bin/env sh
#
# Verifies that tink-gm-crypto is still compatible with a given version of
# com.google.crypto.tink:tink by running the full unit test suite against it.
#
# Usage:
#   ./scripts/verify-tink-version.sh [tink-version]
#
# If no version is given, the version declared by the <tink.version> property
# in pom.xml is used.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "usage: $0 [tink-version]"
  exit 0
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(
    sed -n 's:.*<tink\.version>\([^<]*\)</tink\.version>.*:\1:p' \
      "$PROJECT_DIR/pom.xml" | head -n 1
  )
fi
if [ -z "$VERSION" ]; then
  echo "error: no version given and <tink.version> not found in pom.xml" >&2
  exit 2
fi

MVN="$PROJECT_DIR/mvnw"
if [ ! -x "$MVN" ]; then
  MVN=mvn
fi

echo "==> Verifying tink-gm-crypto against com.google.crypto.tink:tink:$VERSION"
echo "==> Running: $MVN -B test -Dtink.version=$VERSION"

cd "$PROJECT_DIR" || exit 3
"$MVN" -B test "-Dtink.version=$VERSION"
status=$?
if [ "$status" -ne 0 ]; then
  echo "FAILED: build/tests not green against tink $VERSION (exit code $status)"
  exit "$status"
fi
echo "SUCCESS: all tests pass against tink $VERSION"
echo "==> Please record this result in COMPATIBILITY.md (see that file for the matrix format)."
