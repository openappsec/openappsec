include_directories(${PROJECT_SOURCE_DIR}/attachments/kernel_modules/core/include/common_is)

add_executable(cpnano_debug cpnano_debug.cc)

install(TARGETS cpnano_debug DESTINATION bin)
install(TARGETS cpnano_debug DESTINATION orchestration)
