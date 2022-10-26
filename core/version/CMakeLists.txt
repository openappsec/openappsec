set(VERSION_VARS_H_FILE ${CMAKE_CURRENT_BINARY_DIR}/version_vars.h)
set(BUILD_SCRIPT build_version_vars_h.py)
add_custom_command(
    OUTPUT ${VERSION_VARS_H_FILE}
    COMMAND CI_PIPELINE_ID=00000001 CI_BUILD_REF_NAME=open-source python3 ${BUILD_SCRIPT} "userspace" > ${VERSION_VARS_H_FILE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${BUILD_SCRIPT}
)

add_library(version version.cc ${VERSION_VARS_H_FILE})
target_include_directories(version PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(version_ut)
