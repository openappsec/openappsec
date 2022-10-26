add_definitions(-DUSERSPACE)

add_subdirectory(evaluators)
add_library(generic_rulebase generic_rulebase.cc rulebase_config.cc triggers_config.cc parameters_config.cc generic_rulebase_context.cc zones_config.cc zone.cc assets_config.cc match_query.cc)
