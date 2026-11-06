----------------------------------------------------------------------------
-- LuaSec 1.3.2
--
-- Copyright (C) 2009-2023 PUC-Rio
--
-- Author: Pablo Musa
-- Author: Tomas Guisasola
---------------------------------------------------------------------------

local socket = require("socket")
local ssl    = require("ssl")
local ltn12  = require("ltn12")
local http   = require("socket.http")
local url    = require("socket.url")

local try    = socket.try

--
-- Module
--
local _M = {
  _VERSION   = "1.3.2",
  _COPYRIGHT = "LuaSec 1.3.2 - Copyright (C) 2009-2023 PUC-Rio",
  PORT       = 443,
  TIMEOUT    = 60
}

-- TLS configuration
local cfg = {
  protocol = "any",
  options  = {"all", "no_sslv2", "no_sslv3", "no_tlsv1"},
  verify   = "none",
}

--------------------------------------------------------------------
-- Auxiliar Functions
--------------------------------------------------------------------

-- Insert default HTTPS port.
local function default_https_port(u)
   return url.build(url.parse(u, {port = _M.PORT}))
end

-- Convert an URL to a table according to Luasocket needs.
local function urlstring_totable(url, body, result_table)
   url = {
      url = default_https_port(url),
      method = body and "POST" or "GET",
      sink = ltn12.sink.table(result_table)
   }
   if body then
      url.source = ltn12.source.string(body)
      url.headers = {
         ["content-length"] = #body,
         ["content-type"] = "application/x-www-form-urlencoded",
      }
   end
   return url
end

-- Forward calls to the real connection object.
local function reg(conn)
   local mt = getmetatable(conn.sock).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)
                         return method(self.sock, ...)
                      end
      end
   end
end

-- Format the host and port used by an HTTP CONNECT request.
local function proxy_authority(host, port)
   host = tostring(host):gsub("^%[(.*)%]$", "%1")
   if host:find(":", 1, true) then
      host = "[" .. host .. "]"
   end
   return host .. ":" .. tostring(port)
end

-- Send a CONNECT request and consume its complete response header block.
local function connect_proxy(sock, tunnel)
   local authority = proxy_authority(tunnel.host, tunnel.port)
   local request = "CONNECT " .. authority .. " HTTP/1.1\r\n"
      .. "Host: " .. authority .. "\r\n"
   if tunnel.user ~= nil then
      local credentials = tunnel.user .. ":" .. (tunnel.password or "")
      local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
      local encoded = credentials:gsub(".", function (character)
         local byte = string.byte(character)
         local bits = ""
         for shift = 7, 0, -1 do
            bits = bits .. (byte % (2 ^ (shift + 1)) - byte % (2 ^ shift) > 0 and "1" or "0")
         end
         return bits
      end) .. string.rep("0", (6 - (#credentials * 8) % 6) % 6)
      encoded = encoded:gsub("%d%d%d%d%d%d", function (bits)
         local value = 0
         for index = 1, 6 do
            value = value * 2 + (bits:sub(index, index) == "1" and 1 or 0)
         end
         return alphabet:sub(value + 1, value + 1)
      end)
      local remainder = #credentials % 3
      encoded = encoded .. (remainder == 1 and "==" or remainder == 2 and "=" or "")
      request = request .. "Proxy-Authorization: Basic " .. encoded .. "\r\n"
   end
   request = request .. "\r\n"

   local sent, send_error = sock:send(request)
   if not sent or send_error then
      sock:close()
      return nil, send_error
   end

   local status, receive_error = sock:receive("*l")
   if not status or receive_error then
      sock:close()
      return nil, receive_error
   end
   status = status:gsub("\r$", "")

   while true do
      local header, header_error = sock:receive("*l")
      if not header or header_error then
         sock:close()
         return nil, header_error
      end
      header = header:gsub("\r$", "")
      if header == "" then
         break
      end
   end

   local code = status:match("^HTTP/%d+%.%d+%s+(%d%d%d)")
   if not code then
      sock:close()
      return nil, status
   end
   if tonumber(code) < 200 or tonumber(code) >= 300 then
      sock:close()
      return nil, "proxy CONNECT failed: " .. status
   end
   return true
end

-- Return a function which performs the SSL/TLS connection.
local function tcp(params)
   params = params or {}
   -- Default settings
   for k, v in pairs(cfg) do 
      params[k] = params[k] or v
   end
   -- Force client mode
   params.mode = "client"
   -- 'create' function for LuaSocket
   return function ()
      local conn = {}
      conn.sock = try(socket.tcp())
      local st = getmetatable(conn.sock).__index.settimeout
      function conn:settimeout(...)
         return st(self.sock, _M.TIMEOUT)
      end
      -- Replace TCP's connection function
      function conn:connect(host, port)
         try(self.sock:connect(host, port))
         local tunnel = params.proxy_tunnel
         if tunnel then
            try(connect_proxy(self.sock, tunnel))
         end
         self.sock = try(ssl.wrap(self.sock, params))
         self.sock:sni(tunnel and tunnel.host or host)
         self.sock:settimeout(_M.TIMEOUT)
         try(self.sock:dohandshake())
         reg(self)
         return 1
      end
      return conn
  end
end

--------------------------------------------------------------------
-- Main Function
--------------------------------------------------------------------

-- Make a HTTP request over secure connection.  This function receives
--  the same parameters of LuaSocket's HTTP module (except 'proxy' and
--  'redirect') plus LuaSec parameters.
--
-- @param url mandatory (string or table)
-- @param body optional (string)
-- @return (string if url == string or 1), code, headers, status
--
local function request(url, body)
  local result_table = {}
  local stringrequest = type(url) == "string"
  if stringrequest then
    url = urlstring_totable(url, body, result_table)
  else
    url.url = default_https_port(url.url)
  end
  if http.PROXY or url.proxy then
    return nil, "proxy not supported"
  elseif url.redirect then
    return nil, "redirect not supported"
  elseif url.create then
    return nil, "create function not permitted"
  end
  -- New 'create' function to establish a secure connection
  url.create = tcp(url)
  local res, code, headers, status = http.request(url)
  if res and stringrequest then
    return table.concat(result_table), code, headers, status
  end
  return res, code, headers, status
end

--------------------------------------------------------------------------------
-- Export module
--

_M.request = request
_M.tcp = tcp

return _M
