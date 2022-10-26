add_subdirectory(package)

add_executable(attachment_registration_manager main.cc)

target_link_libraries(attachment_registration_manager
        -Wl,--start-group
        ${COMMON_LIBRARIES}

        generic_rulebase
        generic_rulebase_evaluators
        ip_utilities
        version
        signal_handler

	attachment_registrator
	http_transaction_data
        -Wl,--end-group
)

install(TARGETS attachment_registration_manager DESTINATION bin)
install(TARGETS attachment_registration_manager DESTINATION attachment_registration_manager_service/bin)

gen_package(
	install-cp-nano-attachment-registration-manager.sh
	attachment_registration_manager_service
	./install-attachment-registration-manager.sh
	Check Point Attachment Registration Manager Nano Service Version ${PACKAGE_VERSION} Install Package
)
