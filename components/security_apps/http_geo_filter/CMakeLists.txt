include_directories(../waap/include)
include_directories(../waap/waap_clib)
include_directories(../../attachment-intakers/nginx_attachment)

add_library(http_geo_filter http_geo_filter.cc)
