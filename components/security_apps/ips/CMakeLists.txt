include_directories(include)

add_library(ips
    ips_comp.cc
    ips_entry.cc
    ips_signatures.cc
    simple_protection.cc
    compound_protection.cc
    ips_configuration.cc
    helper_open_source.cc
    ips_basic_policy.cc
    snort_basic_policy.cc
    ips_metric.cc
    ips_common_types.cc
)

add_subdirectory(ips_ut)
