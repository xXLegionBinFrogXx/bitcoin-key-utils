cmake_minimum_required(VERSION 3.24)

include(FetchContent)
FetchContent_Declare(
  doctest
  URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.zip
)
FetchContent_MakeAvailable(doctest)

# Make doctest's CMake helpers visible (provides doctest_discover_tests)
list(APPEND CMAKE_MODULE_PATH "${doctest_SOURCE_DIR}/scripts/cmake")
include(doctest)  # defines doctest_discover_tests()

add_executable(bitcoin_key_utils_tests
  doctest_my_lib.cpp
)

# Link against your static lib (keeps tests hermetic)
target_link_libraries(bitcoin_key_utils_tests PRIVATE bitcoin_key_utils-static)

# Include paths if tests include project headers directly
target_include_directories(bitcoin_key_utils_tests PRIVATE
  ${doctest_SOURCE_DIR}   
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../external/bitcoin-core
)

# Auto-register tests with CTest (enumerates [doctest] cases at build time)
doctest_discover_tests(bitcoin_key_utils_tests
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
