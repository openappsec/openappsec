include_directories(${PROJECT_SOURCE_DIR}/core/include/)

link_directories(${Boost_LIBRARY_DIRS})
link_directories(${ZLIB_ROOT}/lib)

link_directories(${ZLIB_ROOT}/lib)
link_directories(${CMAKE_BINARY_DIR}/core)
link_directories(${CMAKE_BINARY_DIR}/core/compression)

SET(EXECUTABLE_NAME "nginx_conf_collector_bin")
add_executable(${EXECUTABLE_NAME} nginx_conf_collector.cc fog_connection.cc)
target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "NGINX_CONF_COLLECTOR_VERSION=\"$ENV{CI_PIPELINE_ID}\"")

target_link_libraries(${EXECUTABLE_NAME}
        shell_cmd
        mainloop
        messaging
        event_is
        metric
        compression_utils
        z
        nginx_utils
        time_proxy
        debug_is
        version
        report
        config
        environment
        curl_http_client
        singleton
        rest
        boost_context
        boost_regex
        pthread
)

install(TARGETS ${EXECUTABLE_NAME} DESTINATION bin)
install(PROGRAMS ${EXECUTABLE_NAME} DESTINATION central_nginx_manager/bin RENAME cp-nano-nginx-conf-collector)
