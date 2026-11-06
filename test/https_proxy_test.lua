package.path = "src/?.lua;" .. package.path

local function assert_equal(actual, expected, message)
   if actual ~= expected then
      error((message or "values differ") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual), 2)
   end
end

local function assert_match(value, pattern, message)
   if not tostring(value):match(pattern) then
      error((message or "value did not match") .. ": " .. tostring(value), 2)
   end
end

local socket_state = {}
local ssl_state = {}

local function socket_try(value, error_message)
   if not value then
      error(error_message, 0)
   end
   return value
end

package.preload["socket"] = function ()
   return {
      tcp = function ()
         return socket_state.raw
      end,
      try = socket_try
   }
end
package.preload["ssl"] = function ()
   return {
      wrap = function (raw, params)
         table.insert(socket_state.events, "wrap")
         assert_equal(raw, socket_state.raw, "TLS wrapped a different socket")
         socket_state.wrapped_params = params
         return ssl_state.tls
      end
   }
end
package.preload["ltn12"] = function ()
   return { sink = { table = function () return function () end end } }
end
package.preload["socket.http"] = function ()
   return {}
end
package.preload["socket.url"] = function ()
   return {
      parse = function () return {} end,
      build = function (value) return value end
   }
end

local https = require("https")

local function new_socket(response, send_result, send_error)
   socket_state.events = {}
   socket_state.sent = nil
   socket_state.closed = 0
   socket_state.wrapped_params = nil
   local lines = response
   local raw = {}
   local methods = {}
   function methods:settimeout(timeout)
      table.insert(socket_state.events, "raw-timeout:" .. tostring(timeout))
      return 1
   end
   function methods:connect(host, port)
      table.insert(socket_state.events, "connect:" .. host .. ":" .. tostring(port))
      return 1
   end
   function methods:send(data)
      table.insert(socket_state.events, "send")
      socket_state.sent = data
      if send_result == false then
         return nil, send_error
      end
      return send_result or #data
   end
   function methods:receive(mode)
      assert_equal(mode, "*l", "CONNECT did not read lines")
      table.insert(socket_state.events, "receive")
      local item = table.remove(lines, 1)
      if not item then
         return nil, "closed"
      end
      return item[1], item[2]
   end
   function methods:close()
      socket_state.closed = socket_state.closed + 1
      table.insert(socket_state.events, "close")
      return 1
   end
   getmetatable(raw) -- keep Lua 5.1-compatible syntax obvious
   setmetatable(raw, { __index = methods })
   socket_state.raw = raw
   return raw
end

local function new_tls()
   local tls = {}
   local methods = {}
   function methods:sni(host)
      table.insert(socket_state.events, "sni:" .. tostring(host))
      socket_state.sni = host
      return 1
   end
   function methods:settimeout(timeout)
      table.insert(socket_state.events, "tls-timeout:" .. tostring(timeout))
      return 1
   end
   function methods:dohandshake()
      table.insert(socket_state.events, "handshake")
      return 1
   end
   setmetatable(tls, { __index = methods })
   ssl_state.tls = tls
end

local function connect(tunnel, destination_host, destination_port, response, send_result, send_error)
   new_tls()
   new_socket(response, send_result, send_error)
   local creator = https.tcp(tunnel and { proxy_tunnel = tunnel } or {})
   local conn = creator()
   local ok, err = pcall(function ()
      return conn:connect(destination_host, destination_port)
   end)
   return ok, err
end

local function response(status, headers)
   local lines = { { status } }
   for _, header in ipairs(headers or {}) do
      table.insert(lines, { header })
   end
   table.insert(lines, { "" })
   return lines
end

-- DNS/IPv4 authority, response-header draining, TLS ordering, and origin SNI.
do
   local ok, result = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      response("HTTP/1.1 204 No Content", { "X-Proxy: drained", "Via: fake" }))
   assert_equal(ok, true, "204 CONNECT failed")
   assert_equal(result, 1, "TLS connection result")
   assert_equal(socket_state.sent,
      "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n\r\n",
      "IPv4 CONNECT request")
   assert_equal(socket_state.sni, "origin.example", "origin SNI")
   assert_equal(socket_state.closed, 0, "successful tunnel was closed")
   assert_equal(table.concat(socket_state.events, ","),
      "connect:proxy.example:8080,send,receive,receive,receive,receive,wrap,sni:origin.example,tls-timeout:60,handshake",
      "CONNECT/TLS ordering")
end

-- An IPv4 origin uses an unbracketed CONNECT authority and Host header.
do
   local ok = connect(
      { host = "127.0.0.1", port = 8443 }, "proxy.example", 8080,
      response("HTTP/1.1 200 Connection Established"))
   assert_equal(ok, true, "IPv4 CONNECT failed")
   assert_equal(socket_state.sent,
      "CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n",
      "IPv4 origin CONNECT request")
end

-- Bracketed IPv6 is normalized to exactly one pair of brackets.
do
   local ok = connect(
      { host = "[2001:db8::1]", port = 8443 }, "127.0.0.1", 3128,
      response("HTTP/1.1 200 Connection Established", { "Content-Length: 0" }))
   assert_equal(ok, true, "IPv6 CONNECT failed")
   assert_equal(socket_state.sent,
      "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
      "IPv6 CONNECT request")
   assert_equal(socket_state.sni, "[2001:db8::1]", "IPv6 origin SNI")
end

-- Credentials are already URL-decoded by the caller before reaching LuaSec.
do
   local ok = connect(
      { host = "origin.example", port = 443, user = "proxy user", password = "p@ss:word" },
      "proxy.example", 8080, response("HTTP/1.1 200 OK", { "X-Auth: accepted" }))
   assert_equal(ok, true, "authenticated CONNECT failed")
   assert_equal(socket_state.sent,
      "CONNECT origin.example:443 HTTP/1.1\r\nHost: origin.example:443\r\n"
         .. "Proxy-Authorization: Basic cHJveHkgdXNlcjpwQHNzOndvcmQ=\r\n\r\n",
      "decoded Basic credentials")
end

-- Every non-2xx response is descriptive and closes the raw socket after draining headers.
do
   local ok, err = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      response("HTTP/1.1 407 Proxy Authentication Required", { "Proxy-Authenticate: Basic", "X: drained" }))
   assert_equal(ok, false, "407 CONNECT unexpectedly succeeded")
   assert_equal(err, "proxy CONNECT failed: HTTP/1.1 407 Proxy Authentication Required", "CONNECT status error")
   assert_equal(socket_state.closed, 1, "non-2xx socket close")
   assert_equal(socket_state.events[#socket_state.events - 1], "receive", "non-2xx headers not drained")
end

-- Malformed status lines close the socket without becoming proxy-status errors.
do
   local ok, err = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      response("not an HTTP status"))
   assert_equal(ok, false, "malformed CONNECT unexpectedly succeeded")
   assert_equal(err, "not an HTTP status", "malformed status error")
   assert_equal(socket_state.closed, 1, "malformed status socket close")
end

-- Incomplete headers preserve the socket error and close the raw socket.
do
   local ok, err = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      { { "HTTP/1.1 200 OK" }, { "X: incomplete" }, { nil, "closed" } })
   assert_equal(ok, false, "incomplete CONNECT unexpectedly succeeded")
   assert_equal(err, "closed", "incomplete response error")
   assert_equal(socket_state.closed, 1, "incomplete response socket close")
end

-- Status-line read timeouts are not rewritten as proxy errors.
do
   local ok, err = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      { { nil, "timeout" } })
   assert_equal(ok, false, "timeout CONNECT unexpectedly succeeded")
   assert_equal(err, "timeout", "timeout error propagation")
   assert_equal(socket_state.closed, 1, "timeout socket close")
end

-- CONNECT write errors are preserved and close the raw socket.
do
   local ok, err = connect(
      { host = "origin.example", port = 443 }, "proxy.example", 8080,
      response("HTTP/1.1 200 OK"), false, "connection reset")
   assert_equal(ok, false, "write-error CONNECT unexpectedly succeeded")
   assert_equal(err, "connection reset", "write error propagation")
   assert_equal(socket_state.closed, 1, "write-error socket close")
end

-- The direct path remains a plain TCP-to-TLS connection with no CONNECT.
do
   local ok = connect(nil, "direct.example", 443, {})
   assert_equal(ok, true, "direct TLS connection failed")
   assert_equal(socket_state.sent, nil, "direct connection sent CONNECT")
   assert_equal(socket_state.sni, "direct.example", "direct SNI changed")
   assert_equal(socket_state.events[1], "connect:direct.example:443", "direct destination changed")
end

print("https proxy CONNECT tests passed")
