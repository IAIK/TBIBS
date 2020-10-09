cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(ctbibs LANGUAGES C VERSION 1.0 DESCRIPTION "relic-based TBIBS library")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckIncludeFiles)
include(CheckSymbolExists)

function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}")
  endif()
endfunction()

check_c_compiler_flag_and_add(-Wall CC_SUPPORTS_WALL)
check_c_compiler_flag_and_add(-Wshadow CC_SUPPORTS_WSHADOW)
check_c_compiler_flag_and_add(-Werror=implicit-function-declaration CC_SUPPORTS_WERROR_IMPLICIT_FUNCTION_DECLARATION)
check_c_compiler_flag_and_add(-Werror=vla CC_SUPPORTS_WERROR_VLA)

find_package(relic REQUIRED)
find_package(OpenSSL REQUIRED)

# TBIBS library
add_library(tbibs STATIC tbibs.c)
target_include_directories(tbibs PRIVATE ${RELIC_INCLUDE_DIR})
target_link_libraries(tbibs PRIVATE ${RELIC_LIBRARY} OpenSSL::Crypto)

# benchmarks
add_executable(bench bench.c)
target_link_libraries(bench PRIVATE tbibs)

# testing
enable_testing()
add_subdirectory(tests)
