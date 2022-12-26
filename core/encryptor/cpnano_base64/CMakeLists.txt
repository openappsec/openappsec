add_executable(cpnano_base64 cpnano_base64.cc base64.cc)
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COMPILE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_LINK_FLAGS}")

add_custom_command(TARGET cpnano_base64
    POST_BUILD
    COMMAND strip $<TARGET_FILE:cpnano_base64> -o $<TARGET_FILE:cpnano_base64>.strip
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cpnano_base64>.strip ${CMAKE_INSTALL_PREFIX}/bin/$<TARGET_FILE:cpnano_json>.strip
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cpnano_base64>.strip ${CMAKE_INSTALL_PREFIX}/orchestration/$<TARGET_FILE:cpnano_json>
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cpnano_base64>.strip ${CMAKE_INSTALL_PREFIX}/wlp_standalone/$<TARGET_FILE:cpnano_json>
)

install(TARGETS cpnano_base64 DESTINATION bin/)
