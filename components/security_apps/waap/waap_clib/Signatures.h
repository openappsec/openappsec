// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __SIGNATURES_H__
#define __SIGNATURES_H__

#include "Waf2Regex.h"
#include "picojson.h"
#include <boost/regex.hpp>

class Signatures {
private:
    // json parsed sources (not really needed once data is loaded)
    picojson::value::object sigsSource;
    bool error;
public:
    Signatures(const std::string& filepath);
    ~Signatures();

    bool fail();

    std::shared_ptr<Waap::RegexPreconditions> m_regexPreconditions;

    // Regexes loaded from compiled signatures
    const Regex words_regex;
    const Regex specific_acuracy_keywords_regex;
    const Regex pattern_regex;
    const Regex un_escape_pattern;
    const Regex quotes_ev_pattern;
    const Regex comment_ev_pattern;
    const Regex quotes_space_ev_pattern;
    const Regex allowed_text_re;
    const Regex pipe_split_re;
    const Regex semicolon_split_re;
    const Regex longtext_re;
    const Regex nospaces_long_value_re;
    const Regex good_header_name_re;
    const Regex good_header_value_re;
    const std::set<std::string> ignored_for_nospace_long_value;
    const std::set<std::string> global_ignored_keywords;
    const std::set<std::string> global_ignored_patterns;
    const std::set<std::string> url_ignored_keywords;
    const std::set<std::string> url_ignored_patterns;
    const Regex url_ignored_re;
    const std::set<std::string> header_ignored_keywords;
    const std::set<std::string> header_ignored_patterns;
    const Regex header_ignored_re;
    const std::map<std::string, std::vector<std::string>> filter_parameters;
    const std::map<std::string, std::vector<std::string>> m_attack_types;
    const Regex php_serialize_identifier;
    const Regex html_regex;
    const Regex uri_parser_regex;
    const boost::regex confluence_macro_re;
#if 0 // Removed by Pavel's request. Leaving here in case he'll want to add this back...
    const std::set<std::string> cookie_ignored_keywords;
    const std::set<std::string> cookie_ignored_patterns;
    const Regex cookie_ignored_re;
#endif
    std::map<std::string, Regex*> headers_re;
    const Regex format_magic_binary_re;
    std::map<std::string, Regex*> params_type_re;

    // Signatures for responses
    const Regex resp_hdr_pattern_regex_list;
    const Regex resp_hdr_words_regex_list;
    const Regex resp_body_pattern_regex_list;
    const Regex resp_body_words_regex_list;

    const std::set<std::string> remove_keywords_always;
    const boost::regex user_agent_prefix_re;
    const boost::regex binary_data_kw_filter;
    const boost::regex wbxml_data_kw_filter;

private:
    picojson::value::object loadSource(const std::string& waapDataFileName);
};

#endif
