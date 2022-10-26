include_directories(${ng_module_osrc_zlib_path}/include)
add_definitions(-DZLIB_CONST)

add_library(compression_utils SHARED compression_utils.cc)

add_subdirectory(compression_utils_ut)

install(TARGETS compression_utils DESTINATION lib)
install(TARGETS compression_utils DESTINATION http_transaction_handler_service/lib)
