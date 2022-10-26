link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    logging_ut
    "logging_ut.cc"
    "logging;singleton;connkey;rest;report;agent_details;event_is;metric;version;-lboost_regex;"
)
