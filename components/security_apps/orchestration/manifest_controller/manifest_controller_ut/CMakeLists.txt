link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    manifest_controller_ut
    "manifest_controller_ut.cc"
    "manifest_controller;logging;orchestration_modules;agent_details;agent_details_reporter;version;config;metric;event_is;-lboost_regex"
)
