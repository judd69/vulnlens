#!/usr/bin/env bash
# Downloads the JUnit 5 standalone console launcher (test-only dependency).
# The shipped vulnlens.jar itself has zero dependencies — plain javac output.
set -euo pipefail
VERSION="${1:-1.11.4}"
LIB_DIR="${2:-lib}"
mkdir -p "$LIB_DIR"
JAR="$LIB_DIR/junit-platform-console-standalone-$VERSION.jar"
if [ -f "$JAR" ]; then
  echo "JUnit $VERSION already present: $JAR"
  exit 0
fi
URL="https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/$VERSION/junit-platform-console-standalone-$VERSION.jar"
echo "Downloading JUnit $VERSION ..."
if curl -fsSL --retry 2 -o "$JAR" "$URL"; then
  echo "Saved to $JAR"
else
  echo "!! Download failed (no network?). Tests will be skipped." >&2
  rm -f "$JAR"
  exit 1
fi
