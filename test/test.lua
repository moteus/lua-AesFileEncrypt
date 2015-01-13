local HAS_RUNNER = not not lunit
local lunit = require "lunit"
local AesFileEncrypt = require "AesFileEncrypt"

local IS_LUA52 = _VERSION >= 'Lua 5.2'

local TEST_CASE = assert(lunit.TEST_CASE)

local function hex(str)
  return (string.gsub(str, ".", function(ch)
    return string.format("%.2x", string.byte(ch))
  end))
end

local function return_count(...)
  return select('#', ...), ...
end

local function H(t, b, e)
  local str = ''
  for i = b or 1, e or #t do
    str = str .. (string.char(t[i]))
  end
  return str
end

local pwd    = "123456"
local SALT   = H{0x5D,0x9F,0xF9,0xAE,0xE6,0xC5,0xC9,0x19,0x42,0x46,0x88,0x3E,0x06,0x9D,0x1A,0xA6}
local PVER   = "9aa9"
local data   = "11111111111111111111\r\n22222222222222222222"
local MAC    = "eb048021e72f5e2a7db3"
local etalon = "91aa63f0cb2b92479f89c32eb6b875b8c7d487aa7a8cb3705a5d8d276d6a2e8fc7cad94cc28ed0ad123e"
local AES256 = AesFileEncrypt.AES256

print("------------------------------------")
print("Lua    version: " .. (_G.jit and _G.jit.version or _G._VERSION))
print("AesFileEncrypt: " .. AesFileEncrypt._VERSION)
print("------------------------------------")
print("")

local _ENV = TEST_CASE"AesFileEncrypt"

local fenc

function setup()
  fenc = AesFileEncrypt.new(16)
end

function teardown()
  fenc:destroy()
end

function test_interface()
  assert_function(AesFileEncrypt.new)
  assert_function(AesFileEncrypt.version)
  assert_function(fenc.open)
  assert_function(fenc.close)
  assert_function(fenc.destroy)
  assert_function(fenc.encrypt)
  assert_function(fenc.decrypt)
  assert_function(fenc.set_writer)
  assert_function(fenc.get_writer)
  assert_function(fenc.opened)
  assert_function(fenc.destroyed)
  assert_string(AesFileEncrypt._VERSION)
  assert_number(AesFileEncrypt.AES128)
  assert_number(AesFileEncrypt.AES192)
  assert_number(AesFileEncrypt.AES256)
  assert_number(AesFileEncrypt.AES128_SALT_LENGTH)
  assert_number(AesFileEncrypt.AES192_SALT_LENGTH)
  assert_number(AesFileEncrypt.AES256_SALT_LENGTH)
  assert_number(AesFileEncrypt.AES128_MAC_LENGTH)
  assert_number(AesFileEncrypt.AES192_MAC_LENGTH)
  assert_number(AesFileEncrypt.AES256_MAC_LENGTH)
end

function test_version()
  local n, major, minor, patch, comment = return_count(AesFileEncrypt.version())
  assert_number(major)
  assert_number(minor)
  assert_number(patch)

  local ver = ("%d.%d.%d"):format(major, minor, patch)
  if n ~= 3 then
    assert_equal(4, n)
    assert_string(comment)
    ver = ver .. "-" .. comment
  end

  assert_equal(ver, AesFileEncrypt._VERSION)
end

function test_error()
  assert_error(function() fenc:open(0, pwd, SALT) end)
  assert_error(function() fenc:open(1, pwd, '1') end)
  assert_error(function() fenc:open(1, '1') end)
  assert_error(function() fenc:encrypt("hello") end)
  assert_string(fenc:open(AES256, pwd, SALT))
  assert_error(function() fenc:open(AES256, pwd, SALT) end)
end

function test_encrypt_string()
  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  local edata = assert_string(fenc:encrypt(data))
  local mac   = assert_string(fenc:close())

  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

function test_encrypt_writer()
  local edata = ""
  fenc:set_writer(function(chunk) edata = edata .. chunk end)

  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  assert_nil(fenc:encrypt(data))
  local mac   = assert_string(fenc:close())

  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

function test_encrypt_stream()
  local stream = {
    _data = {}
  }

  function stream:write(chunk)
    table.insert(self._data, chunk)
  end

  function stream:data()
    return table.concat(self._data)
  end

  fenc:set_writer(stream)

  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  assert_nil(fenc:encrypt(data))
  local mac   = assert_string(fenc:close())

  local edata = stream:data()
  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

function test_encrypt_context()
  local edata = {}
  fenc:set_writer(table.insert, edata)

  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  assert_nil(fenc:encrypt(data))
  local mac   = assert_string(fenc:close())

  local edata = table.concat(edata)
  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

if IS_LUA52 then

function test_encrypt_writer_co()
  local edata = ""

  fenc:set_writer(coroutine.yield)

  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  local mac
  local co = coroutine.create(function()
    assert_nil(fenc:encrypt(data))
    mac = assert_string(fenc:close())
  end)

  while(true)do
    local status, chunk = assert_true(coroutine.resume(co))
    if not chunk then break end
    edata = edata .. chunk
  end

  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

function test_encrypt_context_co()
  local edata = ""
  local context = {}
  fenc:set_writer( coroutine.yield, context )

  local salt, pwd_ver = fenc:open(AES256, pwd, SALT)

  assert_string(salt, pwd_ver)
  assert_string(pwd_ver)
  assert_equal(hex(SALT), hex(salt))
  assert_equal(PVER,      hex(pwd_ver))

  local mac
  local co = coroutine.create(function()
    assert_nil(fenc:encrypt(data))
    mac = assert_string(fenc:close())
  end)

  while(true)do
    local status, ctx, chunk = assert_true(coroutine.resume(co))
    if not chunk then break end
    assert_equal(context, ctx)
    edata = edata .. chunk
  end

  assert_equal(MAC,    hex(mac)   )
  assert_equal(etalon, hex(edata) )
end

end

if not HAS_RUNNER then lunit.run() end
