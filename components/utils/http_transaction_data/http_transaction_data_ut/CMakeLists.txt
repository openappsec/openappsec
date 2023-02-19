include_directories(${CMAKE_SOURCE_DIR}/components/include)

add_unit_test(
    http_transaction_data_ut
    "http_transaction_data_ut.cc"
    "http_transaction_data;http_transaction_data;connkey;${RT_LIBRARY}"
)
