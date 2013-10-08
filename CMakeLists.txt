# Define projects name
# The C tells CMAKE to check for C compilers
project ( AesFileEncrypt C )

# Define minimun version of CMAKE for compatibility
cmake_minimum_required ( VERSION 2.8 )

# Include dist.cmake - defines LuaDist related macros and install paths
# Also include Lua related macros
include ( cmake/dist.cmake )
include ( lua )

# Create and install a Lua module:
# first parameter is module's name (the name that can be required in Lua)
# second and following parameters are the source files (here only one file)
# last parameter is a .def file for exporting symbols from dll produced by MS compilers
install_lua_module ( AesFileEncrypt 
  src/fileenc/aescrypt.c src/fileenc/aeskey.c src/fileenc/aestab.c
  src/fileenc/fileenc.c src/fileenc/hmac.c src/fileenc/prng.c
  src/fileenc/pwd2key.c src/fileenc/sha1.c src/AesFileEncrypt.c
  src/AesFileEncrypt.def src/l52util.c
)

SET_SOURCE_FILES_PROPERTIES(
  src/fileenc/fileenc.c src/fileenc/hmac.c src/fileenc/pwd2key.c src/AesFileEncrypt.c
  PROPERTIES COMPILE_DEFINITIONS "USE_SHA1"
)


# Schedules a test, this is optional
add_lua_test ( test/test.lua )

