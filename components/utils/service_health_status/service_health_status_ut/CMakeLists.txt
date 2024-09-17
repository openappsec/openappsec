include_directories(${Boost_INCLUDE_DIRS})
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    service_health_status_ut
    "service_health_status_ut.cc"
    "service_health_status;rest;event_is;connkey;mainloop;encryptor;messaging;-lz;metric;-lboost_regex;-lboost_context;-lcrypto;"
)
