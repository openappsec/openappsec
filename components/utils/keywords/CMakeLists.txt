add_library(keywords keywords_rule.cc single_keyword.cc data_keyword.cc pcre_keyword.cc length_keyword.cc byte_extract_keyword.cc compare_keyword.cc jump_keyword.cc stateop_keyword.cc no_match_keyword.cc)
add_subdirectory(keywords_ut)
