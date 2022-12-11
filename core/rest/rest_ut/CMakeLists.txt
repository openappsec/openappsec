link_directories(${BOOST_ROOT}/lib)
link_directories(${ng_module_osrc_zlib_path}/lib)

add_unit_test(
    rest_server_ut
    "rest_schema_ut.cc;rest_must_param_ut.cc;rest_config_ut.cc"
    "singleton;rest;environment;-lz;shell_cmd;-lboost_filesystem;message;instance_awareness;messaging_buffer;-lz;debug_is;time_proxy;mainloop;agent_details;encryptor;event_is;metric;-lboost_context;-lboost_regex;-lboost_system;-lssl;-lcrypto;connkey"
)
