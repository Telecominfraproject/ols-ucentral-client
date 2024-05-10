cmake_minimum_required(VERSION 3.13)

project(larch-sonic VERSION 0.1.0 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(grpc)

include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

FetchContent_Declare(httplib URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.15.3.zip)
FetchContent_MakeAvailable(httplib)

FetchContent_Declare(GSL GIT_REPOSITORY https://github.com/microsoft/GSL GIT_TAG "v4.0.0" GIT_SHALLOW ON)
FetchContent_MakeAvailable(GSL)

add_subdirectory(protos)

add_library(larch-sonic
    STATIC
        "plat-larch.cpp"
        "utils.cpp"
        "vlan.cpp"
)

target_compile_features(larch-sonic PRIVATE cxx_std_17)

target_link_libraries(larch-sonic
    PRIVATE
        proto-objects
        nlohmann_json::nlohmann_json
        httplib::httplib
        Microsoft.GSL::GSL
)

target_include_directories(larch-sonic
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/../../include
)

set_target_properties(larch-sonic PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

add_custom_target(plat.a
    DEPENDS larch-sonic
    COMMAND ${CMAKE_AR} rcsT ${PROJECT_SOURCE_DIR}/plat.a
        $<TARGET_FILE:larch-sonic>
        /usr/local/lib/libabsl_bad_optional_access.a
        /usr/local/lib/libabsl_bad_variant_access.a
        /usr/local/lib/libabsl_base.a
        /usr/local/lib/libabsl_city.a
        /usr/local/lib/libabsl_civil_time.a
        /usr/local/lib/libabsl_cord.a
        /usr/local/lib/libabsl_cord_internal.a
        /usr/local/lib/libabsl_cordz_functions.a
        /usr/local/lib/libabsl_cordz_handle.a
        /usr/local/lib/libabsl_cordz_info.a
        /usr/local/lib/libabsl_debugging_internal.a
        /usr/local/lib/libabsl_demangle_internal.a
        /usr/local/lib/libabsl_exponential_biased.a
        /usr/local/lib/libabsl_graphcycles_internal.a
        /usr/local/lib/libabsl_hash.a
        /usr/local/lib/libabsl_hashtablez_sampler.a
        /usr/local/lib/libabsl_int128.a
        /usr/local/lib/libabsl_log_severity.a
        /usr/local/lib/libabsl_low_level_hash.a
        /usr/local/lib/libabsl_malloc_internal.a
        /usr/local/lib/libabsl_random_distributions.a
        /usr/local/lib/libabsl_random_internal_platform.a
        /usr/local/lib/libabsl_random_internal_pool_urbg.a
        /usr/local/lib/libabsl_random_internal_randen.a
        /usr/local/lib/libabsl_random_internal_randen_hwaes.a
        /usr/local/lib/libabsl_random_internal_randen_hwaes_impl.a
        /usr/local/lib/libabsl_random_internal_randen_slow.a
        /usr/local/lib/libabsl_random_internal_seed_material.a
        /usr/local/lib/libabsl_random_seed_gen_exception.a
        /usr/local/lib/libabsl_random_seed_sequences.a
        /usr/local/lib/libabsl_raw_hash_set.a
        /usr/local/lib/libabsl_raw_logging_internal.a
        /usr/local/lib/libabsl_spinlock_wait.a
        /usr/local/lib/libabsl_stacktrace.a
        /usr/local/lib/libabsl_status.a
        /usr/local/lib/libabsl_statusor.a
        /usr/local/lib/libabsl_str_format_internal.a
        /usr/local/lib/libabsl_strerror.a
        /usr/local/lib/libabsl_strings.a
        /usr/local/lib/libabsl_strings_internal.a
        /usr/local/lib/libabsl_symbolize.a
        /usr/local/lib/libabsl_synchronization.a
        /usr/local/lib/libabsl_throw_delegate.a
        /usr/local/lib/libabsl_time.a
        /usr/local/lib/libabsl_time_zone.a
        /usr/local/lib/libaddress_sorting.a
        /usr/local/lib/libcares.a
        /usr/local/lib/libcrypto.a
        /usr/local/lib/libgpr.a
        /usr/local/lib/libgrpc++.a
        /usr/local/lib/libgrpc++_reflection.a
        /usr/local/lib/libgrpc.a
        /usr/local/lib/libprotobuf.a
        /usr/local/lib/libre2.a
        /usr/local/lib/libssl.a
        /usr/local/lib/libupb.a
        /usr/local/lib/libz.a
    VERBATIM
)
