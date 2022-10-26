add_subdirectory(cptest)
add_subdirectory(agent_core_utilities)
add_subdirectory(shell_cmd)
add_subdirectory(debug_is)
add_subdirectory(time_proxy)
add_subdirectory(singleton)
add_subdirectory(buffers)
add_subdirectory(mainloop)
add_subdirectory(environment)
add_subdirectory(table)
add_subdirectory(rest)
add_subdirectory(report)
add_subdirectory(logging)
add_subdirectory(connkey)
add_subdirectory(message)
add_subdirectory(config)
add_subdirectory(agent_details)
add_subdirectory(event_is)
add_subdirectory(encryptor)
add_subdirectory(intelligence_is_v2)
add_subdirectory(cpu)
add_subdirectory(memory_consumption)
add_subdirectory(shmem_ipc)
add_subdirectory(shm_pkt_queue)
add_subdirectory(instance_awareness)
add_subdirectory(socket_is)
add_subdirectory(agent_details_reporter)
add_subdirectory(messaging_buffer)
add_subdirectory(metric)
add_subdirectory(version)
add_subdirectory(tenant_manager)
add_subdirectory(compression)
add_subdirectory(attachments)

add_library(ngen_core SHARED ".")
target_link_libraries(
    ngen_core
    -Wl,-whole-archive
    "table;debug_is;shell_cmd;metric;tenant_manager;message;encryptor;time_proxy;singleton;mainloop;environment;logging;report;rest"
    "config;intelligence_is_v2;event_is;memory_consumption;connkey"
    "instance_awareness;socket_is;messaging_buffer;agent_details;agent_details_reporter;buffers;cpu;agent_core_utilities"
    -Wl,-no-whole-archive
)

add_subdirectory(core_ut)

install(TARGETS ngen_core DESTINATION lib)
install(TARGETS ngen_core DESTINATION orchestration/lib)
