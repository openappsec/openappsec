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

#include "WaapResultJson.h"
#include "Waf2Engine.h"
#include "WaapAssetState.h"

std::string buildWaapResultJson(Waf2ScanResult *m_scanResult, const Waf2Transaction &t, bool bSendResponse,
    const std::string &normalizedUri, const std::string &uri, bool bForceBlock,
    bool bForceException)
{
    auto hdr_pairs = t.getHdrPairs();
    auto notes = t.getNotes();
    auto scanResultKeywordCombinations = t.getKeywordsCombinations();
    auto keywordInfo = t.getKeywordInfo();
    auto kvPairs = t.getKvPairs();
    auto scoreArray = t.getScoreArray();

    if (m_scanResult) {
        Waap::Util::Yajl y;
        {
            Waap::Util::Yajl::Map root(y);
            root.gen_key("data");
            {
                Waap::Util::Yajl::Map data(y);

                data.gen_key("transaction");
                {
                    Waap::Util::Yajl::Map transaction(y);
                    transaction.gen_str("time", t.getLogTime());
                    transaction.gen_integer("remote_port", t.getRemotePort());
                    transaction.gen_str("remote_address", t.getRemoteAddr());
                    std::string support_id = t.getTransactionIdStr();
                    transaction.gen_str("support_id", support_id);
                }
                data.gen_key("request");
                {
                    Waap::Util::Yajl::Map request(y);
                    request.gen_str("method", t.getMethod());
                    request.gen_str("uri", normalizedUri);
                    request.gen_str("orig_uri", uri);
                    request.gen_str("ct", t.getContentTypeStr());
                    request.gen_key("headers");
                    {
                        Waap::Util::Yajl::Map headers(y);
                        for (std::vector<std::pair<std::string, std::string> >::iterator it = hdr_pairs.begin();
                            it != hdr_pairs.end();
                            ++it) {
                            headers.gen_str(it->first, it->second);
                        }
                    }
                }
                data.gen_str("ct", t.getContentTypeStr());
            }
            root.gen_key("res");
            {
                Waap::Util::Yajl::Map res(y);
                res.gen_str("param_location", m_scanResult->location);
                res.gen_str("param_name", m_scanResult->param_name);
                res.gen_str("line", m_scanResult->unescaped_line);
                res.gen_key("keyword_matches");
                {
                    Waap::Util::Yajl::Array keyword_matches(y);
                    for (std::vector<std::string>::iterator pM = m_scanResult->keyword_matches.begin();
                        pM != m_scanResult->keyword_matches.end();
                        ++pM) {
                        std::string& m = *pM;
                        keyword_matches.gen_str(m);
                    }
                }
                res.gen_key("ntags");
                {
                    Waap::Util::Yajl::Map ntags(y);
                    for (Waap::Util::map_of_stringlists_t::iterator pKv = m_scanResult->found_patterns.begin();
                        pKv != m_scanResult->found_patterns.end();
                        ++pKv) {
                        ntags.gen_key(pKv->first);
                        {
                            Waap::Util::Yajl::Array ntags_val(y);
                            for (std::vector<std::string>::iterator pV = pKv->second.begin();
                                pV != pKv->second.end();
                                ++pV) {
                                ntags_val.gen_str(*pV);
                            }
                        }
                    }
                }
                res.gen_double("score", t.getScore());
                res.gen_key("scores_array");
                {
                    Waap::Util::Yajl::Array scores_array(y);
                    for (std::vector<double>::iterator pScore = scoreArray.begin();
                        pScore != scoreArray.end();
                        ++pScore) {
                        scores_array.gen_double(*pScore);
                    }
                }
                res.gen_key("keyword_combinations");
                {
                    Waap::Util::Yajl::Array keyword_combinations_array(y);
                    for (std::vector<std::string>::iterator pCombination = scanResultKeywordCombinations.begin();
                        pCombination != scanResultKeywordCombinations.end();
                        ++pCombination) {
                        keyword_combinations_array.gen_str(*pCombination);
                    }
                }
            }

            root.gen_bool("stage1_force_block", bForceBlock);

            if (bForceException) {
                root.gen_bool("stage1_force_exception", bForceException);
            }

            // TODO:: the output of these should be throttled to up to X per minute (or hour).
            // Maybe throttling should be done elsewhere and flag should be present whether to
            // output the data or not (or just assume i m_keywordInfo.size()==0 - don't output).
            root.gen_key("k_api");
            {
                Waap::Util::Yajl::Array k_api(y);
                for (std::vector<DeepParser::KeywordInfo>::const_iterator it = keywordInfo.begin();
                    it != keywordInfo.end();
                    ++it) {
                    const DeepParser::KeywordInfo& keywordInfo = *it;
                    Waap::Util::Yajl::Map k_api_kw(y);
                    k_api_kw.gen_str("type", keywordInfo.getType());
                    k_api_kw.gen_str("name", keywordInfo.getName());
                    k_api_kw.gen_str("value", keywordInfo.getValue());
                    k_api_kw.gen_integer("len", keywordInfo.getValue().length());
                }
            }
            root.gen_key("x_kvs");
            {
                Waap::Util::Yajl::Map x_kvs(y);
                for (std::vector<std::pair<std::string, std::string> >::iterator it = kvPairs.begin();
                    it != kvPairs.end();
                    ++it) {
                    std::string& k = it->first;
                    std::string& v = it->second;
                    x_kvs.gen_str(k, v);
                }
            }

            root.gen_str("x_body", t.getRequestBody());
            if (!notes.empty()) {
                root.gen_key("notes");
                Waap::Util::Yajl::Array jsNotes(y);
                for (std::vector<std::string>::const_iterator it = notes.begin(); it != notes.end(); ++it) {
                    jsNotes.gen_str(*it);
                }
            }

            root.gen_bool("send_response", bSendResponse);
            root.gen_bool("login_url", false);
        }

        return (bSendResponse ? "1" : "0") + y.get_json_str();
    }
    else {
        Waap::Util::Yajl y;
        {
            Waap::Util::Yajl::Map root(y);
            root.gen_key("data");
            {
                Waap::Util::Yajl::Map data(y);
                data.gen_key("transaction");
                {
                    Waap::Util::Yajl::Map transaction(y);
                    transaction.gen_str("time", t.getLogTime());
                    transaction.gen_integer("remote_port", t.getRemotePort());
                    transaction.gen_str("remote_address", t.getRemoteAddr());
                    std::string support_id = t.getTransactionIdStr();
                    transaction.gen_str("support_id", support_id);
                }
                data.gen_key("request");
                {
                    Waap::Util::Yajl::Map request(y);
                    request.gen_str("method", t.getMethod());
                    request.gen_str("uri", normalizedUri);
                    request.gen_str("orig_uri", uri);
                    request.gen_str("ct", t.getContentTypeStr());
                    request.gen_key("headers");
                    {
                        Waap::Util::Yajl::Map headers(y);
                        for (std::vector<std::pair<std::string, std::string> >::iterator it = hdr_pairs.begin();
                            it != hdr_pairs.end();
                            ++it) {
                            headers.gen_str(it->first, it->second);
                        }
                    }
                }
                data.gen_str("ct", t.getContentTypeStr());
            }

            root.gen_bool("stage1_force_block", bForceBlock);

            if (bForceException) {
                root.gen_bool("stage1_force_exception", bForceException);
            }

            // TODO:: the output of these should be throttled to up to X per minute (or hour).
            // Maybe throttling should be done elsewhere and flag should be present whether to
            // output the data or not (or just assume i m_keywordInfo.size()==0 - don't output).
            root.gen_key("k_api");
            {
                Waap::Util::Yajl::Array k_api(y);
                for (std::vector<DeepParser::KeywordInfo>::const_iterator it = keywordInfo.begin();
                    it != keywordInfo.end();
                    ++it) {
                    const DeepParser::KeywordInfo& keywordInfo = *it;
                    Waap::Util::Yajl::Map k_api_kw(y);
                    k_api_kw.gen_str("type", keywordInfo.getType());
                    k_api_kw.gen_str("name", keywordInfo.getName());
                    k_api_kw.gen_str("value", keywordInfo.getValue());
                    k_api_kw.gen_integer("len", keywordInfo.getValue().length());
                }
            }
            root.gen_key("x_kvs");
            {
                Waap::Util::Yajl::Map x_kvs(y);
                for (std::vector<std::pair<std::string, std::string> >::iterator it = kvPairs.begin();
                    it != kvPairs.end();
                    ++it) {
                    std::string& k = it->first;
                    std::string& v = it->second;
                    x_kvs.gen_str(k, v);
                }
            }

            root.gen_str("x_body", t.getRequestBody());
            if (!notes.empty()) {
                root.gen_key("notes");
                Waap::Util::Yajl::Array jsNotes(y);
                for (std::vector<std::string>::const_iterator it = notes.begin(); it != notes.end(); ++it) {
                    jsNotes.gen_str(*it);
                }
            }

            root.gen_bool("send_response", bSendResponse);
            root.gen_bool("login_url", false);
        }

        return (bSendResponse ? "1" : "0") + y.get_json_str();
    }
}
