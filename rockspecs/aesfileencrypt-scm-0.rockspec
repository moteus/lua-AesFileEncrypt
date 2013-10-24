package = "AesFileEncrypt"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-AesFileEncrypt/archive/master.zip",
  dir = "lua-AesFileEncrypt-master",
}

description = {
  summary = "A simple file encryption library",
  homepage = "https://github.com/moteus/lua-AesFileEncrypt",
  detailed = [[ 
Binding to Dr Brian Gladman's implementation.
Encryption libray use
  a. RFC2898 for key derivation (using HMAC-SHA1)
  b. AES in CTR mode for encryption
  c. HMAC-SHA1 for authentication
  d. A Random Data Pool based on Peter Gutmann's ideas
]];
  license = "GPL",
}

dependencies = {
  "lua >= 5.1",
}


local AES_DIR = 'externals/bgcrypto/aes'
local SHA_DIR = 'externals/bgcrypto/sha'
local ENC_DIR = 'externals/bgcrypto/fileenc'

build = {
  copy_directories = {"test", "examples"},

  type = "builtin",

  modules = {
    AesFileEncrypt = {
      sources = {
        AES_DIR .. '/aescrypt.c', AES_DIR .. '/aeskey.c', AES_DIR .. '/aestab.c',
        SHA_DIR .. '/hmac.c', SHA_DIR .. '/sha1.c', SHA_DIR .. '/pwd2key.c',
        ENC_DIR .. '/fileenc.c', 'src/AesFileEncrypt.c','src/l52util.c',
      },
      defines = { 'USE_SHA1' },
      incdirs = { AES_DIR, SHA_DIR, ENC_DIR },
    },
  },
}

