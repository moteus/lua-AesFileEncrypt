cmake_minimum_required ( VERSION 2.8 )

project ( AesFileEncrypt C )
include ( cmake/dist.cmake )
include ( lua )

include_directories ( ${CMAKE_CURRENT_SOURCE_DIR}/src )

set ( AFE_SOURCE 
  src/fileenc/aescrypt.c src/fileenc/aeskey.c src/fileenc/aestab.c
  src/fileenc/fileenc.c  src/fileenc/hmac.c   src/fileenc/aes_modes.c
  src/fileenc/pwd2key.c  src/fileenc/sha1.c
  src/AesFileEncrypt.c   src/l52util.c
)

set ( AFE_DEFINITIONS USE_SHA1 )

install_lua_module ( AesFileEncrypt ${AFE_SOURCE} LINK ${PDH_LIBRARIES} )

set_target_properties ( AesFileEncrypt PROPERTIES COMPILE_DEFINITIONS "${AFE_DEFINITIONS}" )

install_data ( README.md )

install_test ( test/ )

install_example ( examples/ )
