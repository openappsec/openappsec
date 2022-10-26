include_directories(${CMAKE_SOURCE_DIR}/components/include)
link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    health_check_manager_ut
    "health_check_manager_ut.cc"
    "singleton;mainloop;health_check_manager;event_is;metric;-lboost_regex"
)
