install(FILES install-cp-nano-unified-learning-service.sh DESTINATION unified_learning_service/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-unified-learning-service.cfg DESTINATION unified_learning_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES service-conf.json DESTINATION unified_learning_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-unified-learning-service-debug-conf.json DESTINATION unified_learning_service/conf PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
