link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    service_controller_ut
    "service_controller_ut.cc"
    "service_controller;rest;config;environment;metric;event_is;shell_cmd;orchestration_modules;logging;agent_details;-lboost_regex"
)
