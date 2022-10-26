link_directories(${ng_module_osrc_openssl_path}/lib)
include_directories(${ng_module_osrc_openssl_path}/include)

add_library(message message.cc http_core.cc http_encoder.cc http_decoder.cc)
