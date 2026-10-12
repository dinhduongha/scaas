cmake_minimum_required(VERSION 3.24)
project(scaas_ua_qt LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml QuickTest Test)

find_package(CxxQt QUIET)
if(NOT CxxQt_FOUND)
    include(FetchContent)
    FetchContent_Declare(CxxQt GIT_REPOSITORY https://github.com/kdab/cxx-qt-cmake.git GIT_TAG 0.9.1)
    FetchContent_MakeAvailable(CxxQt)
endif()

cxx_qt_import_crate(MANIFEST_PATH Cargo.toml CRATES scaas_ua_qt LOCKED QT_MODULES Qt::Core Qt::Gui Qt::Qml)
cxx_qt_import_qml_module(scaas_ua_qml_module URI "Scaas.Ua" SOURCE_CRATE scaas_ua_qt)

set(UA_VECTORS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../smartcontracts/vectors/ua" CACHE PATH "kinds.json / structures.json")

add_executable(tst_ua tests/tst_ua.cpp)
target_compile_definitions(tst_ua PRIVATE UA_VECTORS_DIR="${UA_VECTORS_DIR}")
target_link_libraries(tst_ua PRIVATE scaas_ua_qml_module Qt6::QuickTest Qt6::Qml)
add_test(NAME tst_ua COMMAND tst_ua -input ${CMAKE_CURRENT_SOURCE_DIR}/tests/tst_ua.qml)
set_tests_properties(tst_ua PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
