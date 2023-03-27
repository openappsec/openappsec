link_directories(${ng_module_osrc_openssl_path}/lib)
link_directories(${ng_module_osrc_curl_path}/lib)
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    orchestration_ut
    "orchestration_ut.cc"
    "orchestration;rest;manifest_controller;service_controller;orchestration_downloader;agent_details;package_handler;orchestration_modules;orchestration_tools;env_details;environment;config;logging;version;shell_cmd;message;update_communication;agent_details_reporter;connkey;encryptor;metric;ip_utilities;event_is;-lcrypto;-lboost_filesystem;-lboost_regex;-lssl"
)

add_unit_test(
    orchestration_multitenant_ut
    "orchestration_multitenant_ut.cc"
    "orchestration;rest;manifest_controller;service_controller;orchestration_downloader;agent_details;package_handler;orchestration_modules;orchestration_tools;env_details;environment;config;logging;version;shell_cmd;message;update_communication;agent_details_reporter;connkey;encryptor;metric;ip_utilities;event_is;-lcrypto;-lboost_filesystem;-lboost_regex;-lssl;curl"
)
