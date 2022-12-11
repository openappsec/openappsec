link_directories(${ng_module_osrc_openssl_path}/lib)
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    package_handler_ut
    "package_handler_ut.cc"
    "package_handler;orchestration_tools;orchestration_modules;singleton;logging;config;metric;event_is;-lcrypto;-lboost_filesystem;-lboost_regex;-lboost_system"
)
