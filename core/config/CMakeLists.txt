add_library(config config.cc config_specific.cc config_globals.cc)
target_link_libraries(config agent_core_utilities)

link_directories(${BOOST_ROOT}/lib)
