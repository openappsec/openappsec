link_directories(${ng_module_osrc_zlib_path}/lib)

file(COPY test_files DESTINATION .)

add_unit_test(compression_utils_ut "compression_utils_ut.cc" "compression_utils;-lz")