link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    memory_consumption_ut
    "memory_consumption_ut.cc"
    "memory_consumption;event_is;metric;-lboost_regex;"
)
