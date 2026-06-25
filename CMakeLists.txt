cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME blobsso)

# No link-time external deps. The STS POST rides httpfs's core HTTPUtil, and the
# secret-provider API is duckdb core. The Stage-2 SPNEGO path (vendored negotiate
# code from blobhttp) dlopen's GSS-API at RUNTIME — so the only link need is the
# dl loader (${CMAKE_DL_LIBS}; empty/no-op on macOS).

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include third_party/negotiate)

set(EXTENSION_SOURCES src/blobsso_extension.cpp third_party/negotiate/negotiate_auth.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

target_link_libraries(${EXTENSION_NAME} ${CMAKE_DL_LIBS})
target_link_libraries(${LOADABLE_EXTENSION_NAME} ${CMAKE_DL_LIBS})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
