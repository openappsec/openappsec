ADD_SUBDIRECTORY(googletest-release-1.8.0/googletest)

ENABLE_TESTING()

INCLUDE_DIRECTORIES(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} /usr/local/include/graphqlparser)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -g")

FILE(COPY valgrind.supp DESTINATION .)

FILE(COPY kitchen-sink.graphql DESTINATION .)

FILE(COPY kitchen-sink.json DESTINATION .)

FILE(COPY schema-kitchen-sink.graphql DESTINATION .)

FILE(COPY schema-kitchen-sink.json DESTINATION .)

ADD_EXECUTABLE(runTests ParserTests.cpp JsonVisitorTests.cpp BuildCAPI.c)

find_library(LIBGRAPHQLPARSER_LIBRARY libgraphqlparser.dylib HINTS /usr/local/lib)

TARGET_LINK_LIBRARIES(runTests gtest gtest_main ${LIBGRAPHQLPARSER_LIBRARY})

ADD_TEST(gtest_tests runTests)
