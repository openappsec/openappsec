link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    buffers_ut
    "buffers_ut.cc;buffer_eval_ut.cc"
    "buffers;event_is;metric;-lboost_regex"
)
