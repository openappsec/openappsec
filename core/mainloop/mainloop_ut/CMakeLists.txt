if ("${GEN_BUNDLE_VERSION}" STREQUAL "FALSE")
	find_package(Boost REQUIRED)
endif()
link_directories(${Boost_LIBRARY_DIRS})

add_unit_test(
    mainloop_ut
    "mainloop_ut.cc"
    "mainloop;singleton;boost_context;rest;metric;event_is;-lboost_regex"
)

