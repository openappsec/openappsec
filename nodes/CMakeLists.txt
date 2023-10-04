include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OpenSSL_INCLUDE_DIRS})

link_directories(${Boost_LIBRARY_DIRS})
link_directories(${ZLIB_ROOT}/lib)
link_directories(${CMAKE_BINARY_DIR}/core)
link_directories(${CMAKE_BINARY_DIR}/core/compression)

set(COMMON_LIBRARIES "-lngen_core;-lcompression_utils;-lssl;-lcrypto;-lz;-lboost_context;-lboost_atomic;-lboost_regex;-lboost_filesystem;-lboost_system;-lpthread")

include(packaging.cmake)

add_subdirectory(orchestration)
add_subdirectory(agent_cache)
add_subdirectory(http_transaction_handler)
add_subdirectory(attachment_registration_manager)
