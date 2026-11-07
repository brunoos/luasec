-- Regression test for #172/#197
-- Althrough we only use socket.unix, requiring socket.core installs the
-- SIGPIPE ignore handler which is a part of reproducing the issue
require("socket")
local unix = require("socket.unix")
local ssl = require("ssl")
local role, directory, protocol = assert(arg[1]), assert(arg[2]), assert(arg[3])
io.stdout:setvbuf("no")

if role == "server" then
   local listener = assert(unix.stream())
   assert(listener:bind(directory .. "/socket"))
   assert(listener:listen())
   local ready = assert(io.open(directory .. "/ready", "w"))
   assert(ready:write("ready\n"))
   ready:close()
   local peer = assert(listener:accept())
   listener:close()
   peer = assert(ssl.wrap(peer, {
      mode = "server", protocol = protocol,
      certificate = directory .. "/cert.pem", key = directory .. "/key.pem",
   }))
   peer:settimeout(5)
   assert(peer:dohandshake())
   -- Exit without Lua finalizers: close the transport without SSL_shutdown.
   os.exit(0)
end
assert(role == "client", "expected server or client")

local peer = assert(unix.stream())
assert(peer:connect(directory .. "/socket"))
peer = assert(ssl.wrap(peer, {
   mode = "client", protocol = protocol, verify = "none",
}))
peer:settimeout(1)
assert(peer:dohandshake())
-- The runner writes this only after wait(1) confirms the server has exited.
local closed = assert(io.open(directory .. "/closed", "r"))
assert(closed:read("*l") == "closed")
closed:close()

print("LuaSec " .. ssl._VERSION .. ", " .. protocol)
-- KEEP_GOING=1 continues past failures so the later sends run too; on an
-- unfixed LuaSec the third send never returns (zero-progress loop).
local keep_going = os.getenv("KEEP_GOING") == "1"
local failed = false
local function fail(message)
   io.stderr:write("FAIL: " .. message .. "\n")
   if not keep_going then os.exit(1) end
   failed = true
end
local data = string.rep("x", 100)
for i, payload in ipairs({data, "x", data, data}) do
   print(string.format("send #%d (%d bytes): calling", i, #payload))
   local sent, err, sent_through = peer:send(payload)
   print(string.format("send #%d: sent=%s error=%s partial=%s",
      i, tostring(sent), tostring(err), tostring(sent_through)))
   -- Do not demand 'bad length': a fix may reject post-fatal I/O earlier.
   -- LuaSocket's send() returns the index through which it sent.  With start=1,
   -- 1 means zero bytes. Some LuaSec versions return 0 here; accept both while
   -- preserving the important condition: no bytes may be reported as sent.
   local bytes_sent = (sent_through == 1 or sent_through == 0) and 0 or sent_through
   if sent ~= nil or type(err) ~= "string" or err == ""
      or bytes_sent ~= 0
      or err == "wantread" or err == "wantwrite" or err == "timeout" then
      fail("expected a terminal error with zero bytes sent")
   end
end
-- After a fatal error, receive() must fail the same way instead of calling
-- into OpenSSL again.
local got, rerr = peer:receive(1)
print(string.format("receive: got=%s error=%s", tostring(got), tostring(rerr)))
if got ~= nil or type(rerr) ~= "string" or rerr == ""
   or rerr == "wantread" or rerr == "wantwrite" or rerr == "timeout" then
   fail("expected a terminal error from receive")
end
-- close() must return promptly without attempting SSL_shutdown().
peer:close()
if failed then os.exit(1) end
print("PASS: all operations returned terminal errors without hanging")
