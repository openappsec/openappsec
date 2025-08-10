find_package(CURL REQUIRED)

include_directories(${CURL_INCLUDE_DIRS})
link_directories(${CURL_LIBRARY_DIRS})

add_library(curl_http_client STATIC
    curl_http_client.cc
)

target_link_libraries(curl_http_client ${CURL_LIBRARIES})
