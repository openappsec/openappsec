link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    downloader_ut
    "downloader_ut.cc"
    "orchestration;orchestration_downloader;orchestration_modules;orchestration_tools;environment;config;update_communication;metric;event_is;-lcurl;-lcrypto;-lssl;-lboost_regex;-lboost_system"
)
