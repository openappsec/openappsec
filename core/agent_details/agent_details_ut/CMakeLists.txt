include_directories(${CMAKE_SOURCE_DIR}/components/include)
include_directories(${CMAKE_SOURCE_DIR}/cptest/include)
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    agent_details_ut
    "agent_details_ut.cc"
    "singleton;config;agent_details;environment;metric;event_is;-lboost_regex"
)
