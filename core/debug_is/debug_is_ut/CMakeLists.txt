include_directories(${CMAKE_SOURCE_DIR}/components/include)
include_directories(${CMAKE_SOURCE_DIR}/cptest/include)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${BOOST_ROOT}/lib)

add_unit_test(debug_is_ut "debug_ut.cc" "agent_details;metric;event_is;-lboost_regex")
