ADD_DEFINITIONS(-Wno-strict-aliasing)
ADD_DEFINITIONS(-Wno-class-memaccess)
ADD_DEFINITIONS(-Wno-maybe-uninitialized)

include_directories(${Boost_INCLUDE_DIRS})
link_directories(${BOOST_ROOT}/lib ${SHMEM_ROOT}/nginx_cache_shmem)
add_library(shm_pkt_queue SHARED shm_pkt_queue.cc)

target_link_libraries(shm_pkt_queue -lrt)

install(TARGETS shm_pkt_queue DESTINATION lib)

add_subdirectory(shm_pkt_queue_ut)
