add_library(waap
    waap_component.cc
    waap_component_impl.cc
    first_request_object.cc
)

add_subdirectory(waap_clib)
add_subdirectory(reputation)

include_directories(include)
include_directories(reputation)

install(DIRECTORY resources DESTINATION http_transaction_handler_service USE_SOURCE_PERMISSIONS)
