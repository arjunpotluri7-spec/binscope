cmake_minimum_required(VERSION 3.24)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/binscope/version.hpp" _bs_version_line
     REGEX "kVersion = \"[0-9]+\\.[0-9]+\\.[0-9]+\"")
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" BINSCOPE_VERSION "${_bs_version_line}")

project(binscope VERSION ${BINSCOPE_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BINSCOPE_BUILD_TESTS "Build the GoogleTest suite" ON)
option(BINSCOPE_WERROR "Treat compiler warnings as errors" OFF)
option(BINSCOPE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(ENABLE_FUZZERS "Build libFuzzer targets (needs a compiler with -fsanitize=fuzzer)" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

add_library(binscope_warnings INTERFACE)
if(MSVC)
  target_compile_options(binscope_warnings INTERFACE /W4 /permissive-)
  if(BINSCOPE_WERROR)
    target_compile_options(binscope_warnings INTERFACE /WX)
  endif()
else()
  target_compile_options(binscope_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow
                                                     -Wconversion -Wno-sign-conversion)
  if(BINSCOPE_WERROR)
    target_compile_options(binscope_warnings INTERFACE -Werror)
  endif()
endif()

if(BINSCOPE_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all
                      -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(binscope
  src/lib/bytes.cpp
  src/lib/common.cpp
  src/lib/config.cpp
  src/lib/diff.cpp
  src/lib/elf.cpp
  src/lib/entropy.cpp
  src/lib/findings.cpp
  src/lib/json.cpp
  src/lib/macho.cpp
  src/lib/pe.cpp
  src/lib/report.cpp
  src/lib/text.cpp
)
target_include_directories(binscope PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
                                    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/lib)
target_link_libraries(binscope PRIVATE binscope_warnings)

# The CLI lives in a small library so tests can drive it in-process.
add_library(binscope_cli STATIC src/cli/cli.cpp src/cli/io.cpp src/cli/log.cpp)
target_include_directories(binscope_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/cli)
target_link_libraries(binscope_cli PUBLIC binscope PRIVATE binscope_warnings)

add_executable(binscope_exe src/cli/main.cpp)
set_target_properties(binscope_exe PROPERTIES OUTPUT_NAME binscope)
target_link_libraries(binscope_exe PRIVATE binscope_cli binscope_warnings)

# Portable fuzz-smoke driver: replays the seed corpus plus deterministic mutations.
add_executable(fuzz_smoke fuzz/fuzz_smoke.cpp)
target_link_libraries(fuzz_smoke PRIVATE binscope binscope_warnings)

if(ENABLE_FUZZERS)
  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
  check_cxx_source_compiles(
    "#include <cstddef>
     #include <cstdint>
     extern \"C\" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }"
    BINSCOPE_HAVE_LIBFUZZER)
  unset(CMAKE_REQUIRED_FLAGS)
  if(BINSCOPE_HAVE_LIBFUZZER)
    add_executable(fuzz_parse fuzz/fuzz_parse.cpp)
    target_compile_options(fuzz_parse PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_parse PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_parse PRIVATE binscope)
  else()
    message(WARNING "ENABLE_FUZZERS is ON but the compiler lacks libFuzzer; skipping fuzz_parse")
  endif()
endif()

if(BINSCOPE_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.18.0
    GIT_SHALLOW TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  enable_testing()
  add_executable(binscope_tests
    tests/test_bytes.cpp
    tests/test_entropy.cpp
    tests/test_elf.cpp
    tests/test_macho.cpp
    tests/test_pe.cpp
    tests/test_malformed.cpp
    tests/test_findings.cpp
    tests/test_score.cpp
    tests/test_config.cpp
    tests/test_diff.cpp
    tests/test_output.cpp
    tests/test_cli.cpp
    tests/test_regression.cpp
  )
  target_include_directories(binscope_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_compile_definitions(binscope_tests PRIVATE
    BINSCOPE_SAMPLES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/samples")
  target_link_libraries(binscope_tests PRIVATE binscope_cli binscope_warnings
                                               GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(binscope_tests DISCOVERY_TIMEOUT 60)

  add_test(NAME fuzz_smoke_quick
           COMMAND fuzz_smoke --iterations 2000 ${CMAKE_CURRENT_SOURCE_DIR}/samples)
endif()
