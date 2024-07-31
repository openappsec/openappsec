include_directories(${PROJECT_SOURCE_DIR}/core/external_sdk/)

add_library(external_sdk_server external_sdk_server.cc)
add_subdirectory(external_sdk_server_ut)
