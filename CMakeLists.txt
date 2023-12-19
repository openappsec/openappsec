cmake_minimum_required (VERSION 2.8.4)
project (ngen)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall -Wno-terminate")

execute_process(COMMAND grep -c "Alpine Linux" /etc/os-release OUTPUT_VARIABLE IS_ALPINE)
if(NOT IS_ALPINE EQUAL "0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Dalpine")
endif()

find_package(Boost REQUIRED)
find_package(ZLIB REQUIRED)
find_package(GTest REQUIRED)

include(cppcheck.cmake)

include_directories(${Boost_INCLUDE_DIRS})
link_directories(${OPENSSL_ROOT_DIR}/lib)
include_directories(${ZLIB_INCLUDE_DIR})
link_directories(${ZLIB_LIBRARY})
include_directories(/usr/include/libxml2)
include_directories(/usr/src/googletest/googlemock/include)

include(unit_test.cmake)

include_directories(external)
include_directories(external/yajl/yajl-2.1.1/include)
include_directories(external/C-Mock/include/cmock)
include_directories(external/picojson)
include_directories(core/include/general)
include_directories(core/include/internal)
include_directories(core/include/services_sdk/interfaces)
include_directories(core/include/services_sdk/resources)
include_directories(core/include/services_sdk/utilities)
include_directories(core/include/attachments)
include_directories(events/include)
include_directories(components/include)

add_subdirectory(build_system)
add_subdirectory(external)
add_subdirectory(core)
add_subdirectory(attachments)
add_subdirectory(components)
add_subdirectory(nodes)
