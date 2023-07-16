include_directories(include)
add_library(
    intelligence_is_v2 intelligence_comp_v2.cc query_request_v2.cc
    intelligence_types_v2.cc query_filter_v2.cc requested_attributes_v2.cc query_types_v2.cc json_stream.cc invalidation.cc
)

add_subdirectory(intelligence_is_v2_ut)
