add_definitions(-DUSERSPACE)

include_directories(include)

add_library(orchestration orchestration_comp.cc hybrid_mode_telemetry.cc)
add_subdirectory(orchestration_tools)
add_subdirectory(modules)
add_subdirectory(downloader)
add_subdirectory(service_controller)
add_subdirectory(package_handler)
add_subdirectory(manifest_controller)
add_subdirectory(update_communication)
add_subdirectory(details_resolver)
add_subdirectory(health_check)
add_subdirectory(env_details)

#add_subdirectory(orchestration_ut)
