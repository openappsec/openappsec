add_library(pm general_adaptor.cc kiss_hash.cc kiss_patterns.cc kiss_pm_stats.cc kiss_thin_nfa.cc kiss_thin_nfa_analyze.cc kiss_thin_nfa_build.cc kiss_thin_nfa_compile.cc pm_adaptor.cc pm_hook.cc debugpm.cc)

add_subdirectory(pm_ut)
