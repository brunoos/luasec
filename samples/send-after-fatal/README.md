# Send after fatal TLS errors

This is a regression harness for the infinite `send()` loop reported in
[LuaSec PR #172](https://github.com/lunarmodules/luasec/pull/172).

The client completes a TLS handshake over a Unix-domain socket.  The server then
exits without a TLS `close_notify`.  Once the client can observe that the peer is
closed, it repeatedly sends with a changing buffer length: 100 bytes, 1 byte,
100 bytes, 100 bytes.

## Running

From this directory with LuaSec, LuaSocket, OpenSSL, and GNU `timeout`
installed:

    ./run.sh

## Expected behavior

Each send must return promptly with a terminal error and report zero bytes as
sent.  The harness deliberately does not require a particular reason such as
"bad length": a fixed implementation may reject post-fatal I/O with another
terminal error.  A `receive()` after the failed sends must also fail with a
terminal error, and `close()` must return promptly.

An unfixed version may spin indefinitely in LuaSocket's send loop, so an
external timeout is used in the script to prevent the process running forever.

By default the client stops at the first failure.  To see the later sends as
well, and so the loop on an unfixed LuaSec, let it continue past failures:

    KEEP_GOING=1 ./run.sh

With OpenSSL 3.5 the third send then never returns and the runner reports the
process timeout after ten seconds.  With OpenSSL 1.1.1 or 3.0, where LuaSec's
old `LSEC_OPENSSL_ERRNO_BUG` workaround is compiled in, the third send returns
"System error" instead and only the nil error of the first send is observed.
