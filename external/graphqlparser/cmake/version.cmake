# Copyright 2019-present, GraphQL Foundation

find_package(Git QUIET)

# default version string
set(LIBGRAPHQLPARSER_VERSION "0.0-dev")

if(GIT_EXECUTABLE AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
  execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                  OUTPUT_VARIABLE LIBGRAPHQLPARSER_VERSION
                  ERROR_QUIET
                  OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  string(SUBSTRING ${LIBGRAPHQLPARSER_VERSION} 1 -1 LIBGRAPHQLPARSER_VERSION)
endif()
