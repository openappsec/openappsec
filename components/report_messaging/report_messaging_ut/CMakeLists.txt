link_directories(${BOOST_ROOT}/lib)

add_unit_test(report_messaging_ut "report_messaging_ut.cc" "report_messaging;report;singleton;-lboost_regex")