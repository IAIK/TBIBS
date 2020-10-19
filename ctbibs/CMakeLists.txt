cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(tbibs LANGUAGES C CXX VERSION 1.0 DESCRIPTION "relic-based TBIBS library")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckIncludeFile)
include(CheckSymbolExists)

function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flag}")
  endif()
endfunction()

function(check_cxx_compiler_flag_and_add flag result)
  check_cxx_compiler_flag("${flag}" ${result})
  if(${result})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
  endif()
endfunction()

check_c_compiler_flag_and_add(-Wall CC_SUPPORTS_WALL)
check_cxx_compiler_flag_and_add(-Wall CXX_SUPPORTS_WALL)
check_c_compiler_flag_and_add(-Wshadow CC_SUPPORTS_WSHADOW)
check_cxx_compiler_flag_and_add(-Wshadow CXX_SUPPORTS_WSHADOW)
check_c_compiler_flag_and_add(-Werror=implicit-function-declaration CC_SUPPORTS_WERROR_IMPLICIT_FUNCTION_DECLARATION)
check_c_compiler_flag_and_add(-Werror=vla CC_SUPPORTS_WERROR_VLA)

find_package(relic REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(cgreen) # for tests
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.65.0 COMPONENTS timer)

# check for endian.h
check_include_file("endian.h" HAVE_ENDIAN_H)
if (NOT HAVE_ENDIAN_H)
  message(FATAL_ERROR "endian.h is required but could not be found")
endif()
# check for open_memstream
check_symbol_exists(open_memstream stdio.h HAVE_OPEN_MEMSTREAM)

# TBIBS library
add_library(tbibs SHARED tbibs.c tbibs.cpp)
set_target_properties(tbibs PROPERTIES VERSION ${PROJECT_VERSION})
target_include_directories(tbibs PRIVATE ${RELIC_INCLUDE_DIR})
target_link_libraries(tbibs PRIVATE ${RELIC_LIBRARY} OpenSSL::Crypto)

configure_file(tbibs.pc.in tbibs.pc @ONLY)

# benchmarks
if (Boost_FOUND)
  add_executable(bench bench.cpp)
  target_link_libraries(bench PRIVATE tbibs Boost::timer)
endif()

# testing
enable_testing()
add_subdirectory(tests)

# install tbibs
install(TARGETS tbibs
        EXPORT tbibs-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_BINARY_DIR}/tbibs.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(FILES tbibs.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/)
install(EXPORT tbibs-targets
        NAMESPACE tbibs::
        FILE tbibs-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tbibs)
