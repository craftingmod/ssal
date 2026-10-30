#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "Usage: bash scripts/make-userdata.sh OUTPUT SIZE (e.g. /src/out/userdata-test.img 256M)" >&2
  exit 2
fi
output=$1
size=$2
if [ -e "$output" ]; then
  echo "Refusing to overwrite: $output" >&2
  exit 1
fi
mkdir -p "$(dirname "$output")"
truncate -s "$size" "$output"
mkfs.ext4 -F -b 4096 -m 0 -L ssal-data "$output"
e2fsck -fn "$output"
