#!/bin/bash

PATTERN_FILE="$1"

mapfile -t patterns < "$PATTERN_FILE"
mapfile -t actual

OK=true

if [ "${#patterns[@]}" != "${#actual[@]}" ]; then
    echo "--- $PATTERN_FILE"
    echo "+++ actual"
    echo "@@ line count: expected ${#patterns[@]}, got ${#actual[@]} @@"
    OK=false
fi

n=$(( ${#patterns[@]} < ${#actual[@]} ? ${#patterns[@]} : ${#actual[@]} ))
for (( i = 0; i < n; i++ )); do
    if ! printf '%s' "${actual[$i]}" | grep -qE "${patterns[$i]}"; then
        echo "--- $PATTERN_FILE"
        echo "+++ actual"
        echo "@@ line $((i+1)) @@"
        echo "-${patterns[$i]}"
        echo "+${actual[$i]}"
        OK=false
    fi
done

$OK && exit 0 || exit 1
