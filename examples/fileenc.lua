local AesFileEncrypt = require "AesFileEncrypt"

math.randomseed(os.time())
function rand_bytes(n)
  local t = {}
  for i = 1, n do table.insert(t, string.char(math.random(256)-1)) end
  return table.concat(t)
end

local PVER_LENGTH = 2
local SALT_LENGTH = 16
local MAC_LENGTH  = 10
local AES256      = 3
local PASSWORD    = "1234567890"
local SALT        = rand_bytes(SALT_LENGTH)
------------------------------------------
-- encrypt

local ifile = "test.dat"
local ofile = "test.enc"

local i = assert(io.open(ifile, "rb"))
local o = assert(io.open(ofile, "wb+"))

local fenc = AesFileEncrypt.new():set_writer(o)
o:write(fenc:open(AES256, PASSWORD, SALT))

while true do
  local chunk = i:read(1024)
  if not chunk then break end
  fenc:encrypt(chunk)
end

o:write(fenc:close())
o:close()
i:close()

------------------------------------------
-- decrypt

local ifile = "test.enc"
local ofile = "test.dec"

local i = assert(io.open(ifile, "rb"))
local o = assert(io.open(ofile, "wb+"))

fenc:set_writer(o)
local salt,  pwd_ver  = i:read(SALT_LENGTH, PVER_LENGTH)
local salt2, pwd_ver2 = fenc:open(AES256, PASSWORD, salt)

assert(pwd_ver2 == pwd_ver)

local mac = ''
while true do
  local chunk = i:read(1024)
  if not chunk then break end
  chunk = mac .. chunk
  mac   = string.sub(chunk, -MAC_LENGTH)
  chunk = string.sub(chunk, 1, -MAC_LENGTH - 1)
  fenc:decrypt(chunk)
end

local mac2 = fenc:close()
o:close()
i:close()

assert(mac == mac2)
