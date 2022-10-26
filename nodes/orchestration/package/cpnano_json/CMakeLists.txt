add_executable(cpnano_json cpnano_json.cc)

install(PROGRAMS $<TARGET_FILE:cpnano_json> DESTINATION bin/)
install(PROGRAMS $<TARGET_FILE:cpnano_json> DESTINATION orchestration/)
