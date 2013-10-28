-- load encrypted lua file and run it.
-- you could use `feleenc.lua` to encrypt any lua file.
-- Example  eload 123456 prog.elua

local AesFileEncrypt = require "AesFileEncrypt"

local PVER_LENGTH = AesFileEncrypt.VER_LENGTH
local AES256      = AesFileEncrypt.AES256
local MAC_LENGTH  = AesFileEncrypt.AES256_MAC_LENGTH
local SALT_LENGTH = AesFileEncrypt.AES256_SALT_LENGTH

local function co_reader(fn)
  local sender, err = coroutine.create(function ()
    local writer = function (chunk)
      return coroutine.yield(chunk)
    end
    fn(writer)
  end)
  if not sender then return nil, err end

  local function reader()
    local ok, data = coroutine.resume(sender, true)
    if ok then return data end
    return nil, data
  end

  return reader
end

local function decrypt(pwd, istream, ostream)
  local salt,  pwd_ver  = istream:read(SALT_LENGTH, PVER_LENGTH)
  if not (salt and pwd_ver)  then return nil, 'invalid stream format' end
  if #pwd_ver ~= PVER_LENGTH then return nil, 'invalid stream format' end

  local fenc = AesFileEncrypt.new()

  local _, pwd_check = fenc:open(AES256, pwd, salt)
  if pwd_check ~= pwd_ver then return nil, 'invalid password' end

  local mac = ''
  while true do
    local chunk = istream:read(1024)
    if not chunk then break end
    chunk = mac .. chunk
    mac   = string.sub(chunk, -MAC_LENGTH)
    chunk = string.sub(chunk, 1, -MAC_LENGTH - 1)
    chunk = fenc:decrypt(chunk)
    ostream:write(chunk)
  end

  local mac_check, chunk = fenc:close()
  ostream:write(chunk)
  if mac_check == mac then return true end
  return nil, 'invalid password'
end

local function decrypt_reader(pwd, istream, do_close)
  local status = {status = true}

  return co_reader(function(writer)
    local stream = {write = function(self, chunk) writer(chunk) end}
    status.status, status.error = decrypt(pwd, istream, stream)
    if do_close then istream:close() end
  end), status
end

local function decrypt_file_reader(pwd, ifile)
  local i, err = io.open(ifile, "rb")
  if not i then return nil, 'can not open input file :' .. ( err or 'unknown error' ) end
  return decrypt_reader(pwd, i, true)
end

local function decrypt_file_load(pwd, ifile)
  local reader, status = assert(decrypt_file_reader(pwd, ifile))
  local fn, err = load(reader)
  if not fn then return nil, err end
  if not status.status then return nil, status.error, fn end
  return fn
end

------------------------------------------
-- main

local password = arg[1]
local ifile    = arg[2]

local usage = [[
eload <password> <ifile>
  password - string up to 128 chars
  ifile    - input file name
]]

if not password then
  io.stderr:write("no password\n")
  return print( usage )
end

if not ifile then
  io.stderr:write("no input file\n")
  return print( usage )
end

local fn, err = decrypt_file_load(password, ifile)

if not fn then
  io.stderr:write("Error: ", err)
  os.exit(1)
end

return fn()
