cmake_minimum_required(VERSION 3.14)
project(libssha)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(FetchContent)
include(FindPkgConfig)

set(ENABLE_TESTS ON CACHE BOOL "Enable building of tests")
set(ENABLE_COVERAGE OFF CACHE BOOL "Enable code coverage targets")

if(ENABLE_COVERAGE)
    message(STATUS "Code coverage enabled")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -O0")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

set(USE_BOTAN ON CACHE BOOL "Use Botan library for cryptographic operations")
if(USE_BOTAN)
    message(STATUS "Using Botan for cryptographic operations")
    if(WIN32)
        set(BOTAN_ROOT "" CACHE PATH "Path to Botan root directory")
        set(BOTAN_INCLUDE_DIRS "${BOTAN_ROOT}/include/botan-3")
        set(BOTAN_LIBRARIES "${BOTAN_ROOT}/lib/botan-3.lib")
    else()
        pkg_check_modules (BOTAN botan-3 REQUIRED)
    endif()
    
    set(BOTAN_PROVIDER_SOURCES
        src/providers/botan/eddsa-key.cpp
        src/providers/botan/edcsa-key.cpp
        src/providers/botan/rsa-key.cpp
        src/providers/botan/eddsa-pub.cpp
        src/providers/botan/edcsa-pub.cpp
        src/providers/botan/rsa-pub.cpp
        src/providers/botan/botan-lock.cpp
        src/providers/botan/botan-lock-provider.cpp
    )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${BOTAN_INCLUDE_DIRS})

if(MSVC)
# NOMINMAX to prevent Windows headers from defining min and max macros
# Define _WIN32_WINNT to Windows 10 (0x0A00) to enable modern APIs
# Disable warnings about DLL-interface (4251, 4275) and deprecated functions (4996)
# Define _CRT_SECURE_NO_WARNINGS to suppress warnings about unsafe C runtime functions
add_definitions(/DNOMINMAX /D_WIN32_WINNT=0x0A00 /wd4251 /wd4275 /wd4996 /D_CRT_SECURE_NO_WARNINGS)
endif()

set(LIBSSHA_FILES 
    src/messages/message.cpp
    src/messages/add-identity.cpp
    src/messages/identities-answer.cpp
    src/messages/lock-message.cpp
    src/messages/sign-request.cpp
    src/messages/sign-response.cpp
    src/messages/extension.cpp
    src/messages/userauth-request.cpp
    src/messages/remove-identity.cpp
    src/extensions/extension-factory.cpp
    src/extensions/openssh-session-bind.cpp
    src/extensions/openssh-restrict-destination.cpp
    src/key/key-factory.cpp
    src/key/key-manager.cpp
    src/key/pub-key.cpp
    src/key/key.cpp
    src/utils/logger.cpp
    src/utils/deserializer.cpp
    src/utils/serializer.cpp
    src/agent/session.cpp
    external/SHA256.cpp
    ${BOTAN_PROVIDER_SOURCES}
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_library(ssha STATIC
    ${LIBSSHA_FILES}
    )

add_subdirectory(examples)

if(ENABLE_TESTS)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.17.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)
enable_testing()
add_subdirectory(tests/unit)
if(NOT WIN32)
add_subdirectory(tests/integration)
endif()
include(CTest)
endif()