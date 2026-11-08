#!/bin/sh
set -eu
cd "$(dirname "$0")"

if [ "${1-}" = --worker ]; then
    directory=$2
    protocol=$3
    server=
    client=
    trap '[ -z "$client" ] || kill "$client" 2>/dev/null || :; [ -z "$server" ] || kill "$server" 2>/dev/null || :' EXIT
    "${LUA:-lua}" reproduce.lua server "$directory" "$protocol" &
    server=$!
    IFS= read -r ready < "$directory/ready"
    [ "$ready" = ready ]
    "${LUA:-lua}" reproduce.lua client "$directory" "$protocol" &
    client=$!
    wait "$server"
    server=
    printf 'closed\n' > "$directory/closed"
    wait "$client"
    client=
    exit 0
fi

# GNU timeout kills the worker's process group, including a spinning Lua client.
# LuaSec's own socket timeout cannot interrupt the old zero-progress C loop.
directory=$(mktemp -d /tmp/luasec-send-XXXXXX)
trap 'rm -rf "$directory"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
    -keyout "$directory/key.pem" -out "$directory/cert.pem" -days 1 \
    > "$directory/certificate.log" 2>&1
mkfifo "$directory/ready" "$directory/closed"
for protocol in tlsv1_2 tlsv1_3; do
    rm -f "$directory/socket"
    status=0
    timeout 10s sh ./run.sh --worker "$directory" "$protocol" || status=$?
    if [ "$status" -eq 124 ]; then
        echo "FAIL: $protocol exceeded the process timeout (possible send loop)" >&2
    elif [ "$status" -gt 128 ]; then
        echo "FAIL: $protocol client killed by signal $((status - 128))" >&2
    elif [ "$status" -ne 0 ]; then
        echo "FAIL: $protocol exited with status $status" >&2
    fi
    [ "$status" -eq 0 ] || exit "$status"
done
