add_executable(cpnano_base64 cpnano_base64.cc base64.cc)
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COMPILE_FLAGS}")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_LINK_FLAGS}")

install(TARGETS cpnano_base64 DESTINATION bin/)
install(TARGETS cpnano_base64 DESTINATION orchestration/)
