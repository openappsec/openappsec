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

#include "Signatures.h"
#include "waap.h"
#include <fstream>

USE_DEBUG_FLAG(D_WAAP);

typedef picojson::value::object JsObj;
typedef picojson::value JsVal;
typedef picojson::value::array JsArr;
typedef std::map<std::string, std::vector<std::string>> filtered_parameters_t;


static std::vector<std::string> to_strvec(const picojson::value::array& jsV)
{
    std::vector<std::string> r;

    for (auto it = jsV.begin(); it != jsV.end(); ++it) {
        r.push_back(it->get<std::string>());
    }

    return r;
}

static std::set<std::string> to_strset(const picojson::value::array& jsA)
{
    std::set<std::string> r;

    for (auto it = jsA.begin(); it != jsA.end(); ++it) {
        r.insert(it->get<std::string>());
    }

    return r;
}

static std::map<std::string, Regex*> to_regexmap(const picojson::value::object& jsO, bool& error)
{
    std::map<std::string, Regex*> r;

    for (auto it = jsO.begin(); it != jsO.end(); ++it) {
        const std::string& n = it->first;
        // convert name to lowercase now (so we don't need to do it at runtime every time).
        std::string n_lower;
        for (std::string::const_iterator pCh = n.begin(); pCh != n.end(); ++pCh) {
            n_lower += std::tolower(*pCh);
        }
        const picojson::value& v = it->second;

        if (error) {
            // stop loading regexes if there's previous error...
            break;
        }

        // Pointers to Regex instances are stored instead of instances themselves to avoid
        // the need to make the Regex objects copyable.
        // However, these pointers must be freed by the holder of the returned map!
        // note: in our case this freeing is happening in the destructor of the WaapAssetState class.
        r[n] = new Regex(v.get<std::string>(), error, n_lower);
    }

    return r;
}

static filtered_parameters_t to_filtermap(const picojson::value::object& JsObj)
{
    filtered_parameters_t result;
    for (auto it = JsObj.begin(); it != JsObj.end(); ++it)
    {
        const std::string parameter = it->first;
        const picojson::value::array& arr = it->second.get<picojson::value::array>();
        result[parameter] = to_strvec(arr);
    }
    return result;
}

Signatures::Signatures(const std::string& filepath) :
    sigsSource(loadSource(filepath)),
    error(false),
    m_regexPreconditions(std::make_shared<Waap::RegexPreconditions>(sigsSource, error)),
    words_regex(
        to_strvec(sigsSource["words_regex_list"].get<picojson::value::array>()),
        error,
        "words_regex_list",
        m_regexPreconditions
    ),
    specific_acuracy_keywords_regex(
        to_strvec(sigsSource["specific_acuracy_keywords_regex_list"].get<picojson::value::array>()),
        error,
        "specific_acuracy_keywords_regex_list",
        m_regexPreconditions
    ),
    pattern_regex(
        to_strvec(sigsSource["pattern_regex_list"].get<picojson::value::array>()),
        error,
        "pattern_regex_list",
        m_regexPreconditions
    ),
    un_escape_pattern(sigsSource["un_escape_pattern"].get<std::string>(), error, "un_escape_pattern"),
    quotes_ev_pattern(sigsSource["quotes_ev_pattern"].get<std::string>(), error, "quotes_ev_pattern"),
    comment_ev_pattern(sigsSource["comment_ev_pattern"].get<std::string>(), error, "comment_ev_pattern"),
    quotes_space_ev_pattern(
        sigsSource["quotes_space_ev_fast_reg"].get<std::string>(), error,
        "quotes_space_ev_fast_reg"
    ),
    allowed_text_re(sigsSource["allowed_text_re"].get<std::string>(), error, "allowed_text_re"),
    pipe_split_re(
        "([\\w\\=\\-\\_\\.\\,\\(\\)\\[\\]\\/\\%\\s]+?)\\||([\\w\\=\\-\\_\\.\\,\\(\\)\\[\\]\\/\\%\\s]+)|\\|()",
        error,
        "pipe_decode"),
    semicolon_split_re("([\\w\\=\\-\\_\\.\\,\\(\\)\\%]+?);|([\\w\\=\\-\\_\\.\\,\\(\\)\\%]+)|;()", error, "sem_decode"),
    longtext_re(sigsSource["longtext_re"].get<std::string>(), error, "longtext_re"),
    nospaces_long_value_re("^[^\\s]{16,}$", error, "nospaces_long_value_re"),
    good_header_name_re(sigsSource["good_header_name_re"].get<std::string>(), error, "good_header_name"),
    good_header_value_re(sigsSource["good_header_value_re"].get<std::string>(), error, "good_header_value"),
    ignored_for_nospace_long_value(
        to_strset(sigsSource["ignored_for_nospace_long_value"].get<picojson::value::array>())),
    global_ignored_keywords(
        to_strset(
            sigsSource["global_ignored"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    global_ignored_patterns(
        to_strset(
            sigsSource["global_ignored"].get<picojson::value::object>()["patterns"].get<picojson::value::array>()
        )
    ),
    url_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_url"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    url_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_url"].get<picojson::value::object>()["patterns"].get<picojson::value::array>()
        )
    ),
    url_ignored_re(
        sigsSource["ignored_for_url"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "url_ignored"
    ),
    header_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_headers"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    header_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_headers"].get<picojson::value::object>()
            ["patterns"].get<picojson::value::array>()
        )
    ),
    header_ignored_re(
        sigsSource["ignored_for_headers"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "header_ignored"
    ),
    filter_parameters(
        to_filtermap(
            sigsSource["filter_parameters"].get<picojson::object>()
        )
    ),
    m_attack_types(
        to_filtermap(
            sigsSource["attack_types_map"].get<picojson::object>()
        )
    ),
    // Removed by Pavel's request. Leaving here in case he'll want to add this back...
#if 0
    cookie_ignored_keywords(
        to_strset(
            sigsSource["ignored_for_cookies"].get<picojson::value::object>()["keys"].get<picojson::value::array>()
        )
    ),
    cookie_ignored_patterns(
        to_strset(
            sigsSource["ignored_for_cookies"].get<picojson::value::object>()
            ["patterns"].get<picojson::value::array>()
        )
    ),
    cookie_ignored_re(
        sigsSource["ignored_for_cookies"].get<picojson::value::object>()["regex"].get<std::string>(),
        error,
        "cookie_ignored"
    ),
#endif
    php_serialize_identifier("^(N;)|^([ibdsOoCcRra]:\\d+)", error, "php_serialize_identifier"),
    html_regex("(<(?>body|head)\\b.*>(?>.|[\\r\\n]){0,400}){2}|<html", error, "htmlRegex"),
    uri_parser_regex("(http|https)://([^/ :]+):?([^/ ]*)(/?[^ #?]*)", error, "uriParserRegex"),
    confluence_macro_re("{[^\"]+:(?>.+\\|)+.+}"),
    headers_re(to_regexmap(sigsSource["headers_re"].get<JsObj>(), error)),
    format_magic_binary_re(sigsSource["format_magic_binary_re"].get<std::string>(), error, "format_magic_binary_re"),
    params_type_re(to_regexmap(sigsSource["format_types_regex_list"].get<JsObj>(), error)),
    resp_hdr_pattern_regex_list(to_strvec(sigsSource["resp_hdr_pattern_regex_list"].get<JsArr>()),
        error, "resp_hdr_pattern_regex_list", nullptr),
    resp_hdr_words_regex_list(to_strvec(sigsSource["resp_hdr_words_regex_list"].get<JsArr>()),
        error, "resp_hdr_words_regex_list", nullptr),
    resp_body_pattern_regex_list(to_strvec(sigsSource["resp_body_pattern_regex_list"].get<JsArr>()),
        error, "resp_body_pattern_regex_list", nullptr),
    resp_body_words_regex_list(to_strvec(sigsSource["resp_body_words_regex_list"].get<JsArr>()),
        error, "resp_body_words_regex_list", nullptr),
    remove_keywords_always(
        to_strset(sigsSource["remove_keywords_always"].get<JsArr>())),
    user_agent_prefix_re(sigsSource["user_agent_prefix_re"].get<std::string>()),
    binary_data_kw_filter(sigsSource["binary_data_kw_filter"].get<std::string>()),
    wbxml_data_kw_filter(sigsSource["wbxml_data_kw_filter"].get<std::string>())
{

}

Signatures::~Signatures()
{
}

bool Signatures::fail()
{
    return error;
}

picojson::value::object Signatures::loadSource(const std::string& waapDataFileName)
{
    picojson::value doc;
    std::ifstream f(waapDataFileName);

    if (f.fail()) {
        dbgError(D_WAAP) << "Failed to open json data file '" << waapDataFileName << "'!";
        error = true;  // flag an error
        return picojson::value::object();
    }

    int length;
    f.seekg(0, std::ios::end);       // go to the end
    length = f.tellg();              // report location (this is the length)
    char* buffer = new char[length]; // allocate memory for a buffer of appropriate dimension
    f.seekg(0, std::ios::beg);       // go back to the beginning
    f.read(buffer, length);          // read the whole file into the buffer
    f.close();

    std::string dataObfuscated(buffer, length);

    delete[] buffer;


    std::stringstream ss(dataObfuscated);

    ss >> doc;

    if (!picojson::get_last_error().empty()) {
        dbgError(D_WAAP) << "WaapAssetState::loadSource('" << waapDataFileName << "') failed (parse error: '" <<
            picojson::get_last_error() << "').";
        error = true;  // flag an error
        return picojson::value::object();
    }

    return doc.get<picojson::value::object>()["waap_signatures"].get<picojson::value::object>();
}
