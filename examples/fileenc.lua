-- @todo optional store pwd_ver value in file format 

local AesFileEncrypt = require "AesFileEncrypt"

math.randomseed(os.time())
function rand_bytes(n)
  local t = {}
  for i = 1, n do table.insert(t, string.char(math.random(256)-1)) end
  return table.concat(t)
end

------------------------------------------
-- CONST

local PVER_LENGTH = 2
local MAC_LENGTH  = 10
local AES256      = 3
local SALT_LENGTH = 16

------------------------------------------
-- encrypt

local function encrypt(ifile, ofile, pwd)
  local i, err = io.open(ifile, "rb")
  if not i then return nil, 'can not open input file :' .. ( err or 'unknown error' ) end
  local o, err = io.open(ofile, "wb+")
  if not o then 
    i:close();
    return nil, 'can not open output file :' .. ( err or 'unknown error' )
  end


  local fenc = AesFileEncrypt.new():set_writer(o)
  o:write(fenc:open(AES256, pwd, rand_bytes(SALT_LENGTH)))

  while true do
    local chunk = i:read(1024)
    if not chunk then break end
    fenc:encrypt(chunk)
  end

  o:write(fenc:close())

  o:close()
  i:close()
  return true
end

------------------------------------------
-- decrypt

local function decrypt(ifile, ofile, pwd)
  local i, err = io.open(ifile, "rb")

  if not i then return nil, 'can not open input file :' .. ( err or 'unknown error' ) end
  local salt,  pwd_ver  = i:read(SALT_LENGTH, PVER_LENGTH)
  if not (salt and pwd_ver)  then i:close(); return nil, 'invalid file format' end
  if #pwd_ver ~= PVER_LENGTH then i:close(); return nil, 'invalid file format' end

  local o, err = io.open(ofile, "wb+")
  if not o then 
    i:close();
    return nil, 'can not open output file :' .. ( err or 'unknown error' )
  end

  local fenc = AesFileEncrypt.new():set_writer(o)

  local _, pwd_check = fenc:open(AES256, pwd, salt)
  if pwd_check ~= pwd_ver then i:close(); return nil, 'invalid password' end


  local mac = ''
  while true do
    local chunk = i:read(1024)
    if not chunk then break end
    chunk = mac .. chunk
    mac   = string.sub(chunk, -MAC_LENGTH)
    chunk = string.sub(chunk, 1, -MAC_LENGTH - 1)
    fenc:decrypt(chunk)
  end

  local mac_check = fenc:close()
  o:close()
  i:close()
  if mac_check == mac then return true end
  return nil, 'invalid password'
end

------------------------------------------
-- main

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

local fn = (action == 'encrypt') and encrypt or decrypt
local ok, err = fn(ifile, ofile, password)

if not ok then
  io.stderr:write("Error: ", err)
  os.exit(1)
end

os.exit(0)