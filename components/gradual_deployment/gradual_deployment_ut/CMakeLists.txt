include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/components/include)

add_unit_test(
    gradual_deployment_ut
    "gradual_deployment_ut.cc"
    "singleton;rest;connkey;${RT_LIBRARY};gradual_deployment;-lboost_system"
)
