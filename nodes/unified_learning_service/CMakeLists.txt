add_subdirectory(package)

SET(EXECUTABLE_NAME "unified_learning_service")

link_directories(${CMAKE_BINARY_DIR}/core)
link_directories(${CMAKE_BINARY_DIR}/core/shmem_ipc)
link_directories(${BOOST_ROOT}/lib)
link_directories(${CMAKE_BINARY_DIR}/components/security_apps/waap/waap_clib)

add_executable(${EXECUTABLE_NAME} main.cc)

target_link_libraries(${EXECUTABLE_NAME}
    -Wl,--start-group
    ${COMMON_LIBRARIES}

    -lshmem_ipc
    hiredis
    xml2
    pcre2-8
    pcre2-posix
    yajl_s
    graphqlparser
    pm

    nginx_attachment
    unified_learning_comp
    UnifiedIndicatorsContainer
    waap_clib

    version
    signal_handler
    generic_rulebase
    generic_rulebase_evaluators
    ip_utilities
    http_transaction_data

    -Wl,--end-group
)

add_dependencies(${EXECUTABLE_NAME} ngen_core)

install(TARGETS ${EXECUTABLE_NAME} DESTINATION bin)
install(TARGETS ${EXECUTABLE_NAME} DESTINATION "${EXECUTABLE_NAME}/bin")

gen_package(
    install-cp-nano-unified-learning-service.sh
    unified_learning_service
    ./install-cp-nano-unified-learning-service.sh
    open-appsec Unified Learning Service Version ${PACKAGE_VERSION} Install Package
)

execute_process(
    COMMAND sh -c "find /usr/lib* -name \"libhiredis.so*\" | awk '{printf $0\";\"}'"
    OUTPUT_VARIABLE hiredis_libs
)
install(FILES ${hiredis_libs} DESTINATION ${EXECUTABLE_NAME}/lib)
