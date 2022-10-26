link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    agent_details_reporter_ut
    "agent_details_reporter_ut.cc"
    "environment;config;rest;event_is;metric;agent_details_reporter;-lboost_regex"
)
