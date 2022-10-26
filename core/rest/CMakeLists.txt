include_directories(${PROJECT_SOURCE_DIR}/components/include)
add_library(rest rest_server.cc rest_conn.cc rest.cc)

add_subdirectory(rest_ut)
