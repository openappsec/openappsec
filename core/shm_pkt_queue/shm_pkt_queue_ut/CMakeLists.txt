include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/fdio_plugin/shm_pkt_queue/include)
include_directories(${CMAKE_SOURCE_DIR}/components/include)

add_unit_test(
    shm_pkt_queue_ut
    "shm_pkt_queue_ut.cc"
    "buffers;shm_pkt_queue;${RT_LIBRARY}"
)
