enable_testing()

function(add_unit_test ut_name ut_sources use_libs)
    add_executable(${ut_name} ${ut_sources})
    target_link_libraries(${ut_name} -Wl,--start-group ${use_libs} debug_is report cptest pthread packet singleton environment metric event_is buffers rest config ${GTEST_BOTH_LIBRARIES} gmock boost_regex pthread dl -Wl,--end-group)

    add_test(NAME ${ut_name}
        COMMAND ${ut_name}
    )
    set_tests_properties(${ut_name} PROPERTIES ENVIRONMENT "CURR_SRC_DIR=${CMAKE_CURRENT_SOURCE_DIR};CI_BUILD_REF_NAME=open-source")
endfunction(add_unit_test)
