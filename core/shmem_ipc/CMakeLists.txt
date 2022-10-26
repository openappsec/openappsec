include_directories(${Boost_INCLUDE_DIRS})

add_library(shmem_ipc SHARED shmem_ipc.c shared_ring_queue.c)

target_link_libraries(shmem_ipc -lrt)

add_subdirectory(shmem_ipc_ut)

install(TARGETS shmem_ipc DESTINATION lib)
install(TARGETS shmem_ipc DESTINATION http_transaction_handler_service/lib)
