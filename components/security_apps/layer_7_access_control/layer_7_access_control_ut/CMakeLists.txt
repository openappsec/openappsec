file(COPY data DESTINATION .)

add_unit_test(
    layer_7_access_control_ut
    "layer_7_access_control_ut.cc"
    "l7_access_control;logging;agent_details;table;singleton;time_proxy;metric;event_is;connkey;http_transaction_data;generic_rulebase;generic_rulebase_evaluators;ip_utilities;intelligence_is_v2"
)
