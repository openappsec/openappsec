include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/components/include)
include_directories(${CMAKE_SOURCE_DIR}/attachments/nginx/nginx_attachment_util)

add_unit_test(
    nginx_attachment_util_ut
    "nginx_attachment_util_ut.cc"
    "nginx_attachment_util;http_configuration"
)
