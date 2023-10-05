execute_process (
	COMMAND sh -c "which redis-server"
	OUTPUT_VARIABLE redis_server_path
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (IS_SYMLINK ${redis_server_path})
    execute_process (
        COMMAND sh -c "readlink -f ${redis_server_path}"
        OUTPUT_VARIABLE redis_server_path
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

execute_process (
	COMMAND sh -c "which redis-cli"
	OUTPUT_VARIABLE redis_cli_path
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process (
	COMMAND sh -c "find /usr/lib -name \"libatomic.so*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE atomic
)

execute_process (
	COMMAND sh -c "find /usr/lib -name \"libjemalloc*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE jemalloc
)

execute_process (
	COMMAND sh -c "find /usr/lib -name \"liblua*\" | awk '{printf \$0\";\"}'"
	OUTPUT_VARIABLE lua
)

install(FILES ${atomic} DESTINATION agent_cache/lib)
install(FILES ${jemalloc} DESTINATION agent_cache/lib)
install(FILES ${lua} DESTINATION agent_cache/lib)
install(FILES install-cp-nano-agent-cache.sh  DESTINATION agent_cache/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cp-nano-agent-cache.cfg DESTINATION agent_cache/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES cache.conf DESTINATION agent_cache/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES ${redis_conf_path}  DESTINATION agent_cache/)
install(FILES ${redis_server_path}  DESTINATION agent_cache/bin/ RENAME redis-server PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
install(FILES ${redis_cli_path}  DESTINATION agent_cache/bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
