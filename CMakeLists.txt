# Minimum CMake version required
cmake_minimum_required(VERSION 3.24)

# Project definition
project(BitcoinKeyUtils VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(FetchContent)
include(CTest)

# Build options
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_EXAMPLES "Build example program" ON)
option(BUILD_SHARED "Build shared library" ON)
option(BUILD_STATIC "Build static library" ON)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BITCOIN_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/bitcoin-core")
set(UPDATE_SCRIPT   "${CMAKE_CURRENT_SOURCE_DIR}/scripts/update_bitcoin_core.sh")

# Curated bitcoin core list logic  
if(NOT EXISTS "${BITCOIN_CORE_DIR}/crypto/sha256.cpp")
  message(STATUS "Curated Bitcoin Core not found — running ${UPDATE_SCRIPT}")
  execute_process(
    COMMAND bash "${UPDATE_SCRIPT}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    RESULT_VARIABLE _upd_rv
  )
  if(NOT _upd_rv EQUAL 0)
    message(FATAL_ERROR "Failed to fetch curated Bitcoin Core sources (exit ${_upd_rv}).")
  endif()
endif()

set(BITCOIN_CORE_STAMP "${BITCOIN_CORE_DIR}/VERSION.txt")

add_custom_command(
  OUTPUT  "${BITCOIN_CORE_STAMP}"
  COMMAND bash "${UPDATE_SCRIPT}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Syncing curated Bitcoin Core sources"
  VERBATIM
)

add_custom_target(update-bitcoin-core DEPENDS "${BITCOIN_CORE_STAMP}")

# Common sources for both libraries
set(LIB_SOURCES
    src/bitcoin_key_utils.cpp
    external/bitcoin-core/base58.cpp
    external/bitcoin-core/bech32.cpp
    external/bitcoin-core/crypto/sha256.cpp
    external/bitcoin-core/crypto/sha256_sse4.cpp
    external/bitcoin-core/crypto/hex_base.cpp
    external/bitcoin-core/crypto/ripemd160.cpp
    external/bitcoin-core/util/strencodings.cpp
  
)

set(PUBLIC_HEADERS
    include/bitcoin_key_utils.h
)

set(BITCOIN_CORE_HEADERS
    external/bitcoin-core/base58.h
    external/bitcoin-core/bech32.h
    external/bitcoin-core/crypto/sha256.h
    external/bitcoin-core/crypto/ripemd160.h
    external/bitcoin-core/util/strencodings.h
    external/bitcoin-core/span.h
    external/bitcoin-core/util/string.h
    external/bitcoin-core/crypto/hex_base.h
    external/bitcoin-core/crypto/common.h
    external/bitcoin-core/compat/endian.h
    external/bitcoin-core/compat/byteswap.h
    external/bitcoin-core/attributes.h
)


# Create shared library target  
if(BUILD_SHARED)

  add_library(bitcoin_key_utils-shared SHARED ${LIB_SOURCES})

  set_target_properties(bitcoin_key_utils-shared PROPERTIES
      OUTPUT_NAME bitcoin_key_utils
      EXPORT_NAME shared
      VERSION ${PROJECT_VERSION}
      SOVERSION ${PROJECT_VERSION_MAJOR}  
  )

  target_include_directories(bitcoin_key_utils-shared
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/bitcoin-core>"
        "$<INSTALL_INTERFACE:include>"
  )
  
  target_sources(bitcoin_key_utils-shared
      PUBLIC
          FILE_SET public_headers
          TYPE HEADERS
          BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
          FILES ${PUBLIC_HEADERS}
      PUBLIC
          FILE_SET bitcoin_headers
         TYPE HEADERS
         BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/external/bitcoin-core
         FILES ${BITCOIN_CORE_HEADERS}
  )

    
    add_library(bitcoin_key_utils::shared ALIAS bitcoin_key_utils-shared)

endif()


# Create static library target  

if(BUILD_STATIC)

add_library(bitcoin_key_utils-static STATIC ${LIB_SOURCES})
set_target_properties(bitcoin_key_utils-static PROPERTIES
    OUTPUT_NAME bitcoin_key_utils
    EXPORT_NAME static
)
target_include_directories(bitcoin_key_utils-static
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/external/bitcoin-core>"
        "$<INSTALL_INTERFACE:include>"
)
target_sources(bitcoin_key_utils-static
    PUBLIC
        FILE_SET public_headers
        TYPE HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        FILES ${PUBLIC_HEADERS}
    PUBLIC
        FILE_SET bitcoin_headers
        TYPE HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/external/bitcoin-core
        FILES ${BITCOIN_CORE_HEADERS}
)


    add_library(bitcoin_key_utils::static ALIAS bitcoin_key_utils-static)

endif()

if(BUILD_EXAMPLES)
  #use static lib for demos

  add_executable(demo examples/demo.cpp)
  target_link_libraries(demo PRIVATE bitcoin_key_utils-static)
  set_target_properties(demo PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

endif()

if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation rules
install(TARGETS bitcoin_key_utils-static bitcoin_key_utils-shared
    EXPORT BitcoinKeyUtilsTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILE_SET public_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bitcoin_key_utils
    FILE_SET bitcoin_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bitcoin_core
)


install(
    EXPORT BitcoinKeyUtilsTargets
    FILE BitcoinKeyUtilsTargets.cmake
    NAMESPACE BitcoinKeyUtils::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BitcoinKeyUtils
)


include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/BitcoinKeyUtilsConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/BitcoinKeyUtilsConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/BitcoinKeyUtilsConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BitcoinKeyUtils
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/BitcoinKeyUtilsConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/BitcoinKeyUtilsConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/BitcoinKeyUtils
)


add_dependencies(bitcoin_key_utils-static update-bitcoin-core)
add_dependencies(bitcoin_key_utils-shared update-bitcoin-core)
