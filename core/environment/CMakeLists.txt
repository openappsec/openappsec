add_library(environment environment.cc context.cc parsing.cc base_evaluators.cc trace.cc span.cc param_attr.cc)

add_subdirectory(environment_ut)
