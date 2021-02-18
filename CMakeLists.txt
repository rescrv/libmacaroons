cmake_minimum_required(VERSION 3.14)
project(libmacaroons
        VERSION 0.4
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(JSON_SUPPORT "Enable support for JSON Macaroons" ON)
option(FUZZ "Build Fuzzing Executable" OFF)
option(WITH_SANITIZERS "Build with sanitizers" OFF)

add_library(macaroons
        base64.c
        explicit_bzero.c
        macaroons.c
        packet.c
        port.c
        sha256.c
        shim.c
        slice.c
        timingsafe_bcmp.c
        tweetnacl.c
        v1.c
        v2.c
        varint.c)

target_include_directories(macaroons
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if (JSON_SUPPORT)
    message(STATUS "Enabling JSON support")
    target_compile_definitions(macaroons PRIVATE MACAROONS_JSON)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    target_compile_definitions(macaroons PRIVATE HAVE_OSX_LIBUTIL_H)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_compile_definitions(macaroons PRIVATE HAVE_BSD_LIBUTIL_H)
    set_target_properties(macaroons PROPERTIES COMPILE_FLAGS "-msse4.1")
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    target_compile_definitions(macaroons PRIVATE HAVE_LIBUTIL_H)
else ()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif ()

# Test
add_executable(serialize_test macaroon-test-serialization.c)
target_link_libraries(serialize_test macaroons)


add_executable(verifier_test macaroon-test-verifier.c)
target_link_libraries(verifier_test macaroons)

# Build fuzzers
if (FUZZ)
    add_executable(fuzz_serializer fuzzer-driver_afl.c fuzzer-serializer.c)
    target_link_libraries(fuzz_serializer macaroons)
endif ()

if (WITH_SANITIZERS)
    set(SANITIZE_ADDRESS ON)
    set(SANITIZE_UNDEFINED ON)
    find_package(Sanitizers)

    add_sanitizers(serialize_test)
    add_sanitizers(verifier_test)
    if (FUZZ)
        add_sanitizers(fuzz_serializer)
    endif ()
endif ()

# Setup unit testing
include(FetchContent)
set(UNITY_EXTENSION_FIXTURE ON CACHE BOOL "")
FetchContent_Declare(
        unity
        GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
)
FetchContent_MakeAvailable(unity)

include(CTest)
add_subdirectory(test/unity)

# Installation
#set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/macaroons)
#install(TARGETS macaroons
#        EXPORT macaroonsTarget
#        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
## Install the single header
#install(FILES macaroons.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
#
#include(CMakePackageConfigHelpers)
#write_basic_package_version_file(
#        ${CMAKE_CURRENT_BINARY_DIR}/cmake/macaroons-version.cmake
#        VERSION ${PROJECT_VERSION}
#        COMPATIBILITY AnyNewerVersion)
#
#install(FILES
#        ${CMAKE_CURRENT_BINARY_DIR}/cmake/macaroons-version.cmake
#        DESTINATION ${INSTALL_CONFIGDIR})
#
#install(EXPORT macaroonsTarget DESTINATION ${INSTALL_CONFIGDIR} FILE macaroons-config.cmake)
