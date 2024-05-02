cmake_minimum_required(VERSION 3.13)

project(larch-sonic VERSION 0.1.0 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(grpc)

add_subdirectory(protos)

add_library(larch-sonic
    STATIC
        "plat-larch.cpp"
)

target_compile_features(larch-sonic PRIVATE cxx_std_17)

target_link_libraries(larch-sonic PRIVATE proto-objects)

target_include_directories(larch-sonic
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/../../include
)

set_target_properties(larch-sonic PROPERTIES
    PREFIX ""
    OUTPUT_NAME "plat"
    ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}
)

add_custom_target(plat.a DEPENDS larch-sonic)
