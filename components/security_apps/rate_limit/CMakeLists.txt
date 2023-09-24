include_directories(../waap/waap_clib)
include_directories(../waap/include)

add_library(rate_limit_comp rate_limit.cc)

add_library(rate_limit_config rate_limit_config.cc)
