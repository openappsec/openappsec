link_directories(${BOOST_ROOT}/lib)
link_directories(${BOOST_ROOT}/lib ${CMAKE_BINARY_DIR}/core/shmem_ipc)

add_unit_test(
    prometheus_ut
    "prometheus_ut.cc"
    "prometheus_comp;logging;agent_details;waap_clib;table;singleton;time_proxy;metric;event_is;connkey;http_transaction_data;generic_rulebase;generic_rulebase_evaluators;ip_utilities;intelligence_is_v2;-lboost_regex;messaging;"
)
