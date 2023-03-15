# Copyright (c) 2013-2014, Ruslan Baratov
# All rights reserved.

# !!! DO NOT PLACE HEADER GUARDS HERE !!!

include(hunter_add_version)
include(hunter_cacheable)
include(hunter_check_toolchain_definition)
include(hunter_cmake_args)
include(hunter_download)
include(hunter_pick_scheme)

hunter_add_version(
    PACKAGE_NAME
    OpenSSL
    VERSION
    "1.1.1s"
    URL
    "https://github.com/openssl/openssl/archive/OpenSSL_1_1_1s.tar.gz"
    SHA1
    1fd24e1a08d706af9a71642b07590d6bb981fe39
)

hunter_add_version(
    PACKAGE_NAME
    OpenSSL
    VERSION
    "1.1.1t"
    URL
    "https://github.com/openssl/openssl/archive/OpenSSL_1_1_1t.tar.gz"
    SHA1
    34ea65451f7fc4625f31ba50f89b3fbea12f13f3
)

if(MINGW)
  hunter_pick_scheme(DEFAULT url_sha1_openssl)
elseif(WIN32)
  if("${HUNTER_OpenSSL_VERSION}" VERSION_LESS "1.1")
    hunter_pick_scheme(DEFAULT url_sha1_openssl_windows)
  else()
    hunter_pick_scheme(DEFAULT url_sha1_openssl_windows_1_1_plus)
  endif()
elseif(APPLE)
  if(IOS)
    hunter_pick_scheme(DEFAULT url_sha1_openssl_ios)
  else()
    hunter_pick_scheme(DEFAULT url_sha1_openssl_macos)
  endif()
else()
  hunter_pick_scheme(DEFAULT url_sha1_openssl)
endif()

if(MINGW)
  hunter_check_toolchain_definition(NAME "__MINGW64__" DEFINED _hunter_mingw64)
  if(_hunter_mingw64)
    hunter_cmake_args(OpenSSL CMAKE_ARGS HUNTER_OPENSSL_MINGW64=TRUE)
  endif()
endif()

hunter_cacheable(OpenSSL)
hunter_download(PACKAGE_NAME OpenSSL PACKAGE_INTERNAL_DEPS_ID "29")