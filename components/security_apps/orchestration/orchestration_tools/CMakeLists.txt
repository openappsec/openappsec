ADD_DEFINITIONS(-Wno-deprecated-declarations)

add_library(orchestration_tools orchestration_tools.cc)

add_subdirectory(orchestration_tools_ut)
