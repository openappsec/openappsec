link_directories(${BOOST_ROOT}/lib)

add_unit_test(
    encryptor_ut
    "encryptor_ut.cc"
    "encryptor;config;singleton;metric;event_is;-lboost_context;-lboost_regex;-lresolv;-lcrypto"
)
