file(COPY offline_intelligence_files_v2 DESTINATION .)
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    intelligence_is_v2_ut
    "query_request_v2_ut.cc;query_response_v2_ut.cc;intelligence_comp_v2_ut.cc" 
    "intelligence_is_v2;singleton;shell_cmd;event_is;metric;message;agent_details;connkey;-lboost_regex")
