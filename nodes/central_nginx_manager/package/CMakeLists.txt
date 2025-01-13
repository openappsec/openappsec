install(FILES install-cp-nano-central-nginx-manager.sh DESTINATION central_nginx_manager PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-central-nginx-manager.cfg  DESTINATION central_nginx_manager/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-central-nginx-manager-conf.json  DESTINATION central_nginx_manager/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-central-nginx-manager-debug-conf.json  DESTINATION central_nginx_manager/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
