link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    health_check_ut
    "health_check_ut.cc"
    "health_check;mainloop;singleton;agent_details;config;logging;metric;event_is;health_check_manager;-lboost_regex;-lboost_system"
)
