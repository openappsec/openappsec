link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    orchestration_modules_ut
    "orchestration_policy_ut.cc;url_parser_ut.cc;package_ut.cc;orchestration_status_ut.cc;data_ut.cc;"
    "orchestration_modules;config;environment;metric;event_is;time_proxy;-lboost_regex;-lboost_system"
)
