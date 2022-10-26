add_definitions(-DUSERSPACE)

add_library(nginx_attachment_util SHARED nginx_attachment_util.cc)

add_subdirectory(nginx_attachment_util_ut)

install(TARGETS nginx_attachment_util DESTINATION lib)
install(TARGETS nginx_attachment_util DESTINATION http_transaction_handler_service/lib)
