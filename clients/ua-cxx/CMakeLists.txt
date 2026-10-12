cmake_minimum_required(VERSION 3.20)
project(scaas_ua_cxx LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)

# Rust side: plain `cargo build --release` (no corrosion: one fewer pinned download; the only thing we need from cargo is the
# staticlib plus the cxx-generated header, both at fixed paths under the target dir).
find_program(CARGO cargo REQUIRED)
set(SCAAS_UA_CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo" CACHE PATH "cargo target dir")
set(_gen "${SCAAS_UA_CARGO_TARGET_DIR}/cxxbridge")
set(_lib "${SCAAS_UA_CARGO_TARGET_DIR}/release/${CMAKE_STATIC_LIBRARY_PREFIX}scaas_ua_cxx${CMAKE_STATIC_LIBRARY_SUFFIX}")
file(GLOB _rs CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs" "${CMAKE_CURRENT_SOURCE_DIR}/../ua-rs/src/*.rs")
add_custom_command(
  OUTPUT "${_lib}" "${_gen}/scaas-ua-cxx/src/lib.rs.h"
  COMMAND ${CMAKE_COMMAND} -E env "CARGO_TARGET_DIR=${SCAAS_UA_CARGO_TARGET_DIR}"
          ${CARGO} build --release --locked --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
  DEPENDS ${_rs} Cargo.toml Cargo.lock build.rs "${CMAKE_CURRENT_SOURCE_DIR}/../ua-rs/Cargo.toml"
  COMMENT "cargo build scaas-ua-cxx")
add_custom_target(scaas_ua_cargo DEPENDS "${_lib}")

add_library(scaas_ua_rust STATIC IMPORTED)
set_target_properties(scaas_ua_rust PROPERTIES IMPORTED_LOCATION "${_lib}")

add_library(scaas_ua STATIC src/scaas_ua.cpp)
add_library(ScaasUa::scaas_ua ALIAS scaas_ua)
add_dependencies(scaas_ua scaas_ua_cargo)
set_source_files_properties(src/scaas_ua.cpp PROPERTIES OBJECT_DEPENDS "${_gen}/scaas-ua-cxx/src/lib.rs.h")
target_include_directories(scaas_ua PUBLIC include PRIVATE "${_gen}")
target_link_libraries(scaas_ua PUBLIC scaas_ua_rust Threads::Threads ${CMAKE_DL_LIBS})

include(CTest)
if(BUILD_TESTING)
  include(FetchContent)
  FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(json)
  set(SCAAS_UA_VECTORS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../smartcontracts/vectors/ua" CACHE PATH "kinds.json / structures.json")
  add_executable(vectors_test tests/vectors_test.cpp)
  target_link_libraries(vectors_test PRIVATE ScaasUa::scaas_ua nlohmann_json::nlohmann_json)
  target_compile_definitions(vectors_test PRIVATE SCAAS_UA_VECTORS_DIR="${SCAAS_UA_VECTORS_DIR}")
  foreach(t table_groups_purposes_constants valid_rows invalid_rows natives_native_space_canonical_ids messages structures)
    add_test(NAME ${t} COMMAND vectors_test ${t})
  endforeach()
endif()
