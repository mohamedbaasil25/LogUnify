#!/usr/bin/env bash
# Download the two jars the Flink image needs into logunify-flink/jars/ and verify their SHA-256 (run on a connected host).
set -euo pipefail
mkdir -p "$(dirname "$0")/../logunify-flink/jars"      # the folder is git-ignored, so a fresh checkout does not have it
cd "$(dirname "$0")/../logunify-flink/jars"
fetch() {  # url sha256
  f="$(basename "$1")"
  [ -f "$f" ] || curl -fsSL -o "$f" "$1"
  echo "$2  $f" | sha256sum -c -
}
fetch https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/3.3.0-1.20/flink-sql-connector-kafka-3.3.0-1.20.jar \
      1086f3eee73d727e234860fcd03adafc0d76f2fc70a25d39c36427693fff749d
fetch https://repo1.maven.org/maven2/com/github/luben/zstd-jni/1.5.6-4/zstd-jni-1.5.6-4.jar \
      793ca8734aa15687e7e64564eab8b6ae9ee2720eae27aa663074682144b1c386
