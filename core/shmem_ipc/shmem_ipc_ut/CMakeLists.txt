add_unit_test(shared_ring_queue_ut "shared_ring_queue_ut.cc" "shmem_ipc;${RT_LIBRARY}")
add_unit_test(shared_ipc_ut "shmem_ipc_ut.cc" "shmem_ipc;${RT_LIBRARY};time_proxy;mainloop;")
