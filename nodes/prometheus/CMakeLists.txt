add_subdirectory(package)

add_executable(prometheus main.cc)

target_link_libraries(prometheus
    -Wl,--start-group
    ${COMMON_LIBRARIES}

    generic_rulebase
    generic_rulebase_evaluators
    ip_utilities
    version
    signal_handler

	prometheus_comp
	http_transaction_data
    -Wl,--end-group
)

add_dependencies(prometheus ngen_core)

install(TARGETS prometheus DESTINATION bin)
install(TARGETS prometheus DESTINATION prometheus_service/bin)

gen_package(
	install-cp-nano-service-prometheus.sh
	prometheus_service
    ./install-cp-nano-prometheus.sh
	Check Point Prometheus Agent Version ${PACKAGE_VERSION} Install Package
)
