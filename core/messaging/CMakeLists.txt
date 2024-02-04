include_directories(include)

add_subdirectory(messaging_comp)
add_subdirectory(connection)
add_subdirectory(messaging_buffer_comp)
add_library(messaging messaging.cc)
target_link_libraries(
    messaging
    "messaging_comp"
    "connection"
    "messaging_buffer_comp"
)
