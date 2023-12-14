install(FILES install-http-transaction-handler.sh  DESTINATION http_transaction_handler_service/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-http-transaction-handler-conf.json  DESTINATION http_transaction_handler_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-http-transaction-handler-conf-container.json  DESTINATION http_transaction_handler_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-http-transaction-handler-debug-conf.json DESTINATION http_transaction_handler_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-http-transaction-handler.cfg DESTINATION http_transaction_handler_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES k8s-log-file-handler.sh DESTINATION http_transaction_handler_service/bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

install(DIRECTORY snort3_to_ips/ DESTINATION http_transaction_handler_service/scripts/snort3_to_ips FILES_MATCHING PATTERN "*" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES snort_to_ips_local.py  DESTINATION http_transaction_handler_service/scripts PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES exception.py  DESTINATION http_transaction_handler_service/scripts PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

#install(DIRECTORY ${ng_module_osrc_pcre2_path}/lib/ DESTINATION http_transaction_handler_service/lib/ FILES_MATCHING PATTERN "libpcre2-8.so*" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
#install(DIRECTORY ${ng_module_osrc_pcre2_path}/lib/ DESTINATION http_transaction_handler_service/lib/ FILES_MATCHING PATTERN "libpcre2-posix.so*" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
#install(RUNTIME_DEPENDENCY_SET xml DESTINATION http_transaction_handler_service/lib/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
