cmake_minimum_required(VERSION 3.10)
project(stupidvnc)

include(CheckIncludeFileCXX)

set(BUILD_SHARED_LIBS TRUE)
if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if (WIN32)
#	set(OPENSSL_ROOT_DIR "Z:/makin3d_sysroot_win64/2.24")
    set(OpenSSL_ROOT "Z:/makin3d_sysroot_win64/2.24")
	set(OPENSSL_INCLUDE_DIR "z:/makin3d_sysroot_win64/2.24/include")
	set(OPENSSL_CRYPTO_LIBRARY "z:/makin3d_sysroot_win64/2.24/lib/libcrypto-3-x64.dll")
#	set(OPENSSL_SSL_LIBRARY "z:/makin3d_sysroot_win64/2.24/lib/libssl-3-x64.dll")
    set(ZLIB_ROOT "z:/makin3d_sysroot_win64/2.24/")
endif()

find_package(ZLIB REQUIRED)
find_package(OpenSSL "3.0")

MESSAGE (STATUS "Found? ${OPENSSL_FOUND}")
MESSAGE (STATUS "Includes: ${OPENSSL_INCLUDE_DIR}")
MESSAGE (STATUS "Crypto library: ${OPENSSL_CRYPTO_LIBRARY}")

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -fvisibility=hidden -fvisibility-inlines-hidden -ggdb2")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")
if (WIN32)
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
else()
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -fsanitize=address -fsanitize=undefined")
endif()

add_library(stupidvnc stupidvnc.cpp ws.cpp )
target_link_libraries(stupidvnc PRIVATE ZLIB::ZLIB )

if (WIN32)
	target_compile_definitions(stupidvnc PRIVATE __STDC_FORMAT_MACROS )
	target_compile_options(stupidvnc PRIVATE -mno-ms-bitfields)
	target_link_libraries(stupidvnc PRIVATE ws2_32)
endif()

if (OPENSSL_FOUND)
	target_link_libraries(stupidvnc PUBLIC OpenSSL::Crypto)
	target_compile_definitions(stupidvnc PRIVATE HAS_OPENSSL)
endif()


add_executable(lsdtest lsdtest.cpp)
target_link_libraries(lsdtest stupidvnc)

check_include_file_cxx("X11/extensions/XTest.h" XTEST_FOUND)
if (XTEST_FOUND)
	add_executable(x11stupidvnc x11stupidvnc.cpp)
	target_link_libraries(x11stupidvnc stupidvnc X11 Xtst Xdamage Xfixes)
endif()
