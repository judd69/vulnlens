#!/usr/bin/env bash
# Regenerates docs/sample-report.html from the checked-in OSV.dev fixture.
# Runs VulnLens's real pipeline (PomParser -> OsvMapper -> ScanEngine -> HtmlReport);
# only the HTTP transport is bypassed — see tools/osv-fixture/README.md for why.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -d "$HOME/workspace/tools/jdk-21.0.12.1+1" ]; then
  export JAVA_HOME="$HOME/workspace/tools/jdk-21.0.12.1+1"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

BUILD_DIR="build"
mkdir -p "$BUILD_DIR/buildtools-classes"
find src/buildtools/java -name '*.java' > "$BUILD_DIR/buildtools-sources.txt"
javac -cp "$BUILD_DIR/classes" -d "$BUILD_DIR/buildtools-classes" @"$BUILD_DIR/buildtools-sources.txt"

java -cp "$BUILD_DIR/classes:$BUILD_DIR/buildtools-classes" \
  dev.vulnlens.buildtools.FixtureMain \
  examples/vulnerable-sample/pom.xml \
  tools/osv-fixture/sample-batch-response.json \
  docs/sample-report.html
