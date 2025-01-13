add_subdirectory(package)

add_executable(cp-nano-central-nginx-manager main.cc)

target_link_libraries(cp-nano-central-nginx-manager
    -Wl,--start-group
    ${COMMON_LIBRARIES}

    generic_rulebase
    generic_rulebase_evaluators
    ip_utilities
    version
    signal_handler

	central_nginx_manager
    nginx_message_reader
    rate_limit_comp
    rate_limit_config
    nginx_utils
	http_transaction_data
    -Wl,--end-group
)

add_dependencies(cp-nano-central-nginx-manager ngen_core)

install(TARGETS cp-nano-central-nginx-manager DESTINATION bin)
install(TARGETS cp-nano-central-nginx-manager DESTINATION central_nginx_manager/bin)

gen_package(
	install-cp-nano-central-nginx-manager.sh
	central_nginx_manager
	./install-cp-nano-central-nginx-manager.sh
	Check Point Central NGINX Manager Nano Service Version ${PACKAGE_VERSION} Install Package
)