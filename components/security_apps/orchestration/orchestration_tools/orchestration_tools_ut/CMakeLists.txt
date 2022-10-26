link_directories(${ng_module_osrc_openssl_path}/lib)

add_unit_test(
    orchestration_tools_ut
    "orchestration_tools_ut.cc"
    "orchestration_modules;orchestration_tools;singleton;-lcrypto;"
)
