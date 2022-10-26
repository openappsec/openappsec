add_subdirectory(package)

add_executable(orchestration_comp main.cc)

target_link_libraries(
    orchestration_comp
    -Wl,--start-group

    ${COMMON_LIBRARIES}

    generic_rulebase
    generic_rulebase_evaluators
    ip_utilities
    http_transaction_data
    version
    signal_handler

    orchestration
    health_check
    health_check_manager
    service_controller
    manifest_controller
    package_handler
    orchestration_modules
    details_resolver
    orchestration_downloader
    update_communication
    orchestration_tools
    messaging_downloader_client
    k8s_policy_gen
    curl

    -Wl,--end-group
)

install(TARGETS orchestration_comp DESTINATION bin)
install(TARGETS orchestration_comp DESTINATION orchestration/bin)

install(FILES package/certificate/ngen.body.crt DESTINATION orchestration/certificate/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES package/certificate/public-keys/cloud-ngen.pem DESTINATION orchestration/certificate/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES package/certificate/public-keys/dev-i2.pem DESTINATION orchestration/certificate/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES package/certificate/public-keys/i2.pem DESTINATION orchestration/certificate/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES package/certificate/public-keys/stg-i2.pem DESTINATION orchestration/certificate/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_regex.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_regex
)
install(FILES ${boost_regex} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_atomic.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_atomic
)
install(FILES ${boost_atomic} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_chrono.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_chrono
)
install(FILES ${boost_chrono} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_context.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_context
)
install(FILES ${boost_context} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_filesystem.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_filesystem
)
install(FILES ${boost_filesystem} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_iostreams.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_iostreams
)
install(FILES ${boost_iostreams} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_system.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_system
)
install(FILES ${boost_system} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_system.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_system
)
install(FILES ${boost_system} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libboost_thread.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE boost_thread
)
install(FILES ${boost_thread} DESTINATION orchestration/lib/boost)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libcrypto.so/{printf $NF\";\"}'"
	OUTPUT_VARIABLE crypto
)
install(FILES ${crypto} DESTINATION orchestration/lib)

execute_process (
	 COMMAND bash -c "ldconfig -p | awk '/libssl.so/{printf $NF\";\"}'"
	 OUTPUT_VARIABLE ssl
)
install(FILES ${ssl} DESTINATION orchestration/lib)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libcurl.so/{sub(/[^/]*$/,\"\", $NF); path=$NF}END{system(\"ls \"path\"libcurl.so*\")}' | awk '{printf $1\";\"}'"
	OUTPUT_VARIABLE curl
)
install(FILES ${curl} DESTINATION orchestration/lib)

execute_process (
	COMMAND bash -c "ldconfig -p | awk '/libz.so/{sub(/[^/]*$/,\"\", $NF); path=$NF}END{system(\"ls \"path\"libz.so*\")}' | awk '{printf $1\";\"}'"
	OUTPUT_VARIABLE z
)
install(FILES ${z} DESTINATION orchestration/lib)


install(DIRECTORY scripts DESTINATION orchestration USE_SOURCE_PERMISSIONS)

gen_help(
	"--token <token>" "Registration token"
	"--fog <fog URL>" "Agents Fog Addresss (valid URL)"
	"--proxy [user:pass@]<proxy URL>:<proxy port>" "Proxy address"
	"--offline_mode" "Run the Orchestration Nano service in offline mode"
	"--external_addresses <IPs list>" "List of Agents Host IP Addresses"
	"--certs-dir <Trusted CA directory>" "Path to the hosts trusted ca directory"
	"--public-key <Public key file path>" "Path to the SSL certificate's public key file (PEM format)"
	"--ignore <ignore packages list>" "List of ignored packages"
	"-ia" "Ignore access control package"
)

set_package_params("--platform x86")

gen_package(
	install-cp-nano-agent.sh
	orchestration
	"./orchestration_package.sh;--x86"
	Check Point Nano Agent Version ${PACKAGE_VERSION} Install Package
)
