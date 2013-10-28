-- @todo optional store pwd_ver value in file format 

local AesFileEncrypt = require "AesFileEncrypt"

local encrypt, decrypt
------------------------------------------
do -- encrypt/decrypt

------------------------------------------
-- CONST

local PVER_LENGTH = AesFileEncrypt.VER_LENGTH
local AES256      = AesFileEncrypt.AES256
local MAC_LENGTH  = AesFileEncrypt.AES256_MAC_LENGTH
local SALT_LENGTH = AesFileEncrypt.AES256_SALT_LENGTH

local function rand_bytes(n)
  local t = {}
  for i = 1, n do table.insert(t, string.char(math.random(256)-1)) end
  return table.concat(t)
end

encrypt = function(pwd, istream, ostream)
  local fenc = AesFileEncrypt.new():set_writer(ostream)
  local salt, pwd_ver = fenc:open(AES256, pwd, rand_bytes(SALT_LENGTH))

  if type(ostream) == 'function' then
    ostream(salt)
    ostream(pwd_ver)
  else
    ostream:write(salt)
    ostream:write(pwd_ver)
  end

  while true do
    local chunk = istream:read(1024)
    if not chunk then break end
    fenc:encrypt(chunk)
  end

  ostream:write((fenc:close()))

  return true
end

decrypt = function(pwd, istream, ostream)
  local salt,  pwd_ver  = istream:read(SALT_LENGTH, PVER_LENGTH)
  if not (salt and pwd_ver)  then return nil, 'invalid stream format' end
  if #pwd_ver ~= PVER_LENGTH then return nil, 'invalid stream format' end

  local fenc = AesFileEncrypt.new():set_writer(ostream)

  local _, pwd_check = fenc:open(AES256, pwd, salt)
  if pwd_check ~= pwd_ver then return nil, 'invalid password' end

  local mac = ''
  while true do
    local chunk = istream:read(1024)
    if not chunk then break end
    chunk = mac .. chunk
    mac   = string.sub(chunk, -MAC_LENGTH)
    chunk = string.sub(chunk, 1, -MAC_LENGTH - 1)
    fenc:decrypt(chunk)
  end

  local mac_check = fenc:close()
  if mac_check == mac then return true end
  return nil, 'invalid password'
end

end


local encrypt_action, decrypt_action
------------------------------------------
-- actions
do

encrypt_action = function(ifile, ofile, pwd)
  local i, err = io.open(ifile, "rb")
  if not i then return nil, 'can not open input file :' .. ( err or 'unknown error' ) end
  local o, err = io.open(ofile, "wb+")
  if not o then 
    i:close();
    return nil, 'can not open output file :' .. ( err or 'unknown error' )
  end

  local ok, err = encrypt(pwd, i, o)

  o:close()
  i:close()

  return ok, err
end

decrypt_action = function(ifile, ofile, pwd)
  local i, err = io.open(ifile, "rb")
  if not i then return nil, 'can not open input file :' .. ( err or 'unknown error' ) end

  local o, err = io.open(ofile, "wb+")
  if not o then 
    i:close();
    return nil, 'can not open output file :' .. ( err or 'unknown error' )
  end

  local ok, err = decrypt(pwd, i, o)

  o:close()
  i:close()

  return ok, err
end

end

------------------------------------------
-- main

math.randomseed(os.time())

local action   = arg[1]
local password = arg[2]
local ifile    = arg[3]
local ofile    = arg[4]

local usage = [[
fileenc <action> <password> <ifile> <ofile>
  action   - encrypt/decrypt
  password - string up to 128 chars
  ifile    - input file name
  ofile    - output file name
]]

if not action then 
  return print( usage )
end

if (action ~= 'encrypt') and (action ~= 'decrypt') then
  io.stderr:write("invalid action: ", action, "\n")
  return print( usage )
end

if not password then
  io.stderr:write("no password\n")
  return print( usage )
end

if not ifile then
  io.stderr:write("no input file\n")
  return print( usage )
end

if not ofile then
  io.stderr:write("no output file\n")
  return print( usage )
end

local fn = (action == 'encrypt') and encrypt_action or decrypt_action
local ok, err = fn(ifile, ofile, password)

if not ok then
  io.stderr:write("Error: ", err)
  os.exit(1)
end

os.exit(0)