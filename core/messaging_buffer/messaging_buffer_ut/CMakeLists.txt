link_directories(${BOOST_ROOT}/lib)

include_directories(${ng_module_osrc_zlib_path}/include)
link_directories(${ng_module_osrc_zlib_path}/lib)

add_unit_test(messaging_buffer_ut "messaging_buffer_ut.cc" "singleton;environment;time_proxy;instance_awareness;messaging_buffer;-lz;encryptor;event_is;metric;-lboost_regex;-lboost_filesystem;-lcrypto;-lboost_system")
