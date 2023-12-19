add_subdirectory(package)

link_directories(${CMAKE_BINARY_DIR}/core/shmem_ipc)
link_directories(${CMAKE_BINARY_DIR}/attachments/nginx/nginx_attachment_util)

add_executable(cp-nano-http-transaction-handler main.cc)

target_link_libraries(cp-nano-http-transaction-handler
	-Wl,--start-group
	${COMMON_LIBRARIES}

	graphqlparser
	xml2
	pcre2-8
	pcre2-posix
	yajl_s
	hiredis

	-lshmem_ipc
	-lnginx_attachment_util

	generic_rulebase
	generic_rulebase_evaluators
	ip_utilities
        version
	signal_handler
	report_messaging

	nginx_attachment
	gradual_deployment
	http_manager_comp
	pm
	waap
	waap_clib
	reputation
	rate_limit_comp
	rate_limit_config
        ips
        keywords
	l7_access_control
	-Wl,--end-group
)

install(TARGETS cp-nano-http-transaction-handler DESTINATION bin)
install(TARGETS cp-nano-http-transaction-handler DESTINATION http_transaction_handler_service/bin)

execute_process (
	COMMAND sh -c "find /usr/lib* -name \"libpcre2-8.so*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE pcre2-8
)
install(FILES ${pcre2-8} DESTINATION http_transaction_handler_service/lib)

execute_process (
	COMMAND sh -c "find /usr/lib* -name \"libpcre2-posix.so*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE pcre2-posix
)
install(FILES ${pcre2-posix} DESTINATION http_transaction_handler_service/lib)

execute_process (
        COMMAND sh -c "find /usr/lib* -name \"libhiredis.so*\" | awk '{printf $0\";\"}'"
        OUTPUT_VARIABLE hiredis
)
install(FILES ${hiredis} DESTINATION http_transaction_handler_service/lib)

execute_process (
	COMMAND sh -c "find /usr/lib* -name \"libxml2.so*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE xml2
)
install(FILES ${xml2} DESTINATION http_transaction_handler_service/lib)

gen_help(
	"--certs-dir <trusted ca directory>" "Path to the hosts trusted ca directory"
)

set_package_params("--platform x86")

gen_package(
	install-cp-nano-service-http-transaction-handler.sh
	http_transaction_handler_service
	./install-http-transaction-handler.sh
	Check Point HTTP Transaction Handler Nano Service Version ${PACKAGE_VERSION} Install Package
)
