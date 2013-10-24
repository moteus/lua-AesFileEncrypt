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

build = {
  copy_directories = {"test", "examples"},

  type = "builtin",

  modules = {
    AesFileEncrypt = {
      sources = {
        'src/fileenc/aescrypt.c','src/fileenc/aeskey.c','src/fileenc/aestab.c',
        'src/fileenc/fileenc.c','src/fileenc/hmac.c','src/fileenc/aes_modes.c',
        'src/fileenc/pwd2key.c','src/fileenc/sha1.c',
        'src/AesFileEncrypt.c','src/l52util.c',
      },
      defines = { 'USE_SHA1' },
    },
  },
}


