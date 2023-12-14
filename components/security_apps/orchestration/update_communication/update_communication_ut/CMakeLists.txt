link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    update_communication_ut
    "local_communication_ut.cc;fog_communication_ut.cc"
    "rest;version;orchestration_modules;update_communication;singleton;config;metric;event_is;logging;agent_details;-lboost_regex;local_policy_mgmt_gen;connkey;"
)
