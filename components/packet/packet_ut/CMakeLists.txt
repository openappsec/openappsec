link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    packet_ut
    "packet_ut.cc"
    "packet;connkey;buffers;environment;metric;event_is;-lboost_regex"
)
