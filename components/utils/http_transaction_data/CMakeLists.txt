add_definitions(-DUSERSPACE)

add_library(http_transaction_data http_transaction_data.cc)

add_subdirectory(http_transaction_data_ut)
