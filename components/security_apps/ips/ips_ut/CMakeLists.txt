link_directories(${CMAKE_BINARY_DIR}/core/shmem_ipc)

add_unit_test(
    ips_ut
    "signatures_ut.cc;entry_ut.cc;component_ut.cc;configuration.cc;rule_selector_ut.cc;compound_ut.cc;resource_ut.cc"
    "ips;keywords;pcre2-8;intelligence_is_v2;logging;compression_utils;agent_details;time_proxy;event_is;table;http_transaction_data;nginx_attachment;connkey;pm;metric;encryptor;generic_rulebase;generic_rulebase_evaluators;compression_utils;ip_utilities;-lboost_regex;-lcrypto;-lz"
)
