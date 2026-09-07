#!/usr/bin/env sh
#
# Verifies that the counterparty-facing reference implementations in
# src/test/java/cc/ddrpa/interop/bc/ truly depend only on JDK + BouncyCastle
# (no Google Tink, no JUnit), by compiling and running them standalone.
#
# This is the guarantee behind the "copy this package to the counterparty" story
# documented in interop/README.md.
#
# Usage:
#   ./scripts/verify-interop-samples.sh
#
# Requirements: JDK 11+ and the org.bouncycastle:bcprov-jdk18on artifact of the
# version declared in pom.xml (fetched into the Maven local repository, e.g. by
# an earlier `./mvnw test`). The script prefers the workspace-local repository
# (target/local-m2) and falls back to ~/.m2.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname "$SCRIPT_DIR")
BC_VERSION=$(
  sed -n 's:.*<bouncycastle\.version>\([^<]*\)</bouncycastle\.version>.*:\1:p' \
    "$PROJECT_DIR/pom.xml" | head -n 1
)
if [ -z "$BC_VERSION" ]; then
  echo "error: <bouncycastle.version> not found in pom.xml" >&2
  exit 2
fi

BC_JAR=""
for base in "$PROJECT_DIR/target/local-m2" "$HOME/.m2/repository"; do
  candidate="$base/org/bouncycastle/bcprov-jdk18on/$BC_VERSION/bcprov-jdk18on-$BC_VERSION.jar"
  if [ -f "$candidate" ]; then
    BC_JAR=$candidate
    break
  fi
done
if [ -z "$BC_JAR" ]; then
  echo "error: bcprov-jdk18on-$BC_VERSION.jar not found (run ./mvnw test once to fetch it)" >&2
  exit 3
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

SRC="$PROJECT_DIR/src/test/java/cc/ddrpa/interop/bc"
if [ ! -d "$SRC" ]; then
  echo "error: $SRC does not exist" >&2
  exit 4
fi

echo "==> Compiling counterparty reference implementations (JDK + bcprov only)"
javac --release 11 -cp "$BC_JAR" -d "$WORK_DIR" "$SRC"/*.java

echo "==> Running BcInteropDemo (self round-trips, no Tink on classpath)"
java -cp "$WORK_DIR:$BC_JAR" cc.ddrpa.interop.bc.BcInteropDemo

echo "==> OK: counterparty samples compile and run with only bcprov on the classpath"
echo "==> In-repo interop self-checks (Tink <-> pure BC) can be run with:"
echo "    ./mvnw test -Dtest='cc.ddrpa.interop.*Test'"
