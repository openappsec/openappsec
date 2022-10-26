include_directories(${ng_module_osrc_zlib_path}/include)
include_directories(${Boost_INCLUDE_DIRS})

add_library(messaging_buffer messaging_buffer.cc event_queue.cc bucket_manager.cc)

add_subdirectory(messaging_buffer_ut)
