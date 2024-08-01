link_directories(${BOOST_ROOT}/lib)

add_unit_test(
        external_sdk_server_ut
        "external_sdk_server_ut.cc"
        "external_sdk_server;mainloop;singleton;rest;environment;time_proxy;logging;event_is;metric;-lboost_context;agent_details;-lboost_regex;messaging;"
)
