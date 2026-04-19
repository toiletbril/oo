#!/usr/bin/env bash
# Line-by-line pattern comparison.
# Each line in PATTERN_FILE is a grep -E extended regex matched against
# the corresponding line of stdin. Allows fuzzy matching like '.*' so
# error message wording can change without updating expected files.
# Exits 0 on full match, 1 with a diff-style report on mismatch.

PATTERN_FILE="$1"

mapfile -t patterns < "$PATTERN_FILE"
mapfile -t actual

ok=true

if [ "${#patterns[@]}" != "${#actual[@]}" ]; then
    echo "--- $PATTERN_FILE"
    echo "+++ actual"
    echo "@@ line count: expected ${#patterns[@]}, got ${#actual[@]} @@"
    ok=false
fi

n=$(( ${#patterns[@]} < ${#actual[@]} ? ${#patterns[@]} : ${#actual[@]} ))
for (( i = 0; i < n; i++ )); do
    if ! printf '%s' "${actual[$i]}" | grep -qE "${patterns[$i]}"; then
        echo "--- $PATTERN_FILE"
        echo "+++ actual"
        echo "@@ line $((i+1)) @@"
        echo "-${patterns[$i]}"
        echo "+${actual[$i]}"
        ok=false
    fi
done

$ok && exit 0 || exit 1
