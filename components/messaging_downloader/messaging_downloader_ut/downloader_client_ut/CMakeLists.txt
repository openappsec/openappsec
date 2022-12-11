link_directories(${BOOST_ROOT}/lib)
include_directories(${CMAKE_SOURCE_DIR}/core/include)
link_directories(${CMAKE_BINARY_DIR}/core/include)

add_unit_test(
    downloader_client_ut
    "downloader_client_ut.cc" 
    "singleton;messaging_downloader_client;time_proxy;mainloop;rest;metric;event_is;message;-lboost_context;agent_core_utilities;orchestration_modules;connkey;-lboost_regex;-lboost_filesystem;-lboost_system"
)
