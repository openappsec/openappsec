add_definitions(-DUSERSPACE)

include_directories(include)

add_library(gradual_deployment gradual_deployment.cc )

add_subdirectory(gradual_deployment_ut)
