#!/usr/bin/env bash
# VulnLens build: compile with plain javac, run the JUnit 5 test suite,
# package a zero-dependency runnable jar, and regenerate docs/sample-report.html.
set -euo pipefail
cd "$(dirname "$0")"

JUNIT_VERSION="1.11.4"
LIB_DIR="lib"
BUILD_DIR="build"
JAR="$BUILD_DIR/vulnlens.jar"

# Prefer the durable Temurin JDK 21 when present (this sandbox's system JDK
# does not persist); otherwise fall back to whatever java/javac is on PATH.
if [ -d "$HOME/workspace/tools/jdk-21.0.12.1+1" ]; then
  export JAVA_HOME="$HOME/workspace/tools/jdk-21.0.12.1+1"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

echo "==> Fetching test dependencies"
./tools/fetch-test-deps.sh "$JUNIT_VERSION" "$LIB_DIR" || true

echo "==> Compiling main sources"
rm -rf "$BUILD_DIR/classes" "$BUILD_DIR/test-classes" "$BUILD_DIR/buildtools-classes"
mkdir -p "$BUILD_DIR/classes" "$BUILD_DIR/test-classes" "$BUILD_DIR/buildtools-classes"
find src/main/java -name '*.java' > "$BUILD_DIR/main-sources.txt"
javac -d "$BUILD_DIR/classes" @"$BUILD_DIR/main-sources.txt"

echo "==> Packaging $JAR"
jar --create --file "$JAR" --main-class dev.vulnlens.VulnLens -C "$BUILD_DIR/classes" .

echo "==> Compiling tests"
JUNIT_JAR=$(ls "$LIB_DIR"/junit-platform-console-standalone-*.jar 2>/dev/null | head -n 1 || true)
if [ -z "$JUNIT_JAR" ]; then
  echo "!! JUnit jar not found in $LIB_DIR — skipping tests"
else
  find src/test/java -name '*.java' > "$BUILD_DIR/test-sources.txt"
  javac -cp "$BUILD_DIR/classes:$JUNIT_JAR" -d "$BUILD_DIR/test-classes" @"$BUILD_DIR/test-sources.txt"
  # test resources (real OSV.dev records used as fixtures)
  if [ -d src/test/resources ]; then
    cp -r src/test/resources/* "$BUILD_DIR/test-classes"/
  fi
  echo "==> Running tests"
  java -jar "$JUNIT_JAR" \
    --class-path "$BUILD_DIR/classes:$BUILD_DIR/test-classes" \
    --scan-class-path \
    --details=tree \
    --fail-if-no-tests
fi

echo "==> Regenerating docs/sample-report.html"
./tools/gen-sample-report.sh

echo "==> Done: $JAR"
