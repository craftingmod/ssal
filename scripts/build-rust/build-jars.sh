#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
sdk="${ANDROID_HOME:-/opt/android-sdk}"
d8="$(ls -d "$sdk"/build-tools/*/lib/d8.jar | sort -V | tail -n1)"
android_jar="$(ls -d "$sdk"/platforms/*/android.jar | sort -V | tail -n1)"
mkdir -p out/bin
build_jar() { # name source class classpath-args...
    local name="$1" src="$2" cls="$3"; shift 3
    local classes="out/jar-classes/$name"
    rm -rf "$classes" && mkdir -p "$classes"
    javac --release 8 "$@" -d "$classes" "$src"
    java -cp "$d8" com.android.tools.r8.D8 --min-api 30 --output "out/bin/$name.jar" "$classes/$cls"
    unzip -l "out/bin/$name.jar" | grep -q classes.dex
}
build_jar fork-probe native/fork-probe/dev/ssal/probe/ForkProbe.java dev/ssal/probe/ForkProbe.class
build_jar input-injector native/input-injector/dev/ssal/input/InputInjector.java dev/ssal/input/InputInjector.class \
    -classpath "$android_jar"
