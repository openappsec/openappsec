// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifdef USE_HYPERSCAN
#include "hyperscan_hook.h"
#include <algorithm>
#include <cctype>

// Helper function to escape regex special characters for literal matching
static std::string escapeRegexChars(const std::string& input) {
    std::string escaped;
    for (char c : input) {
        switch (c) {
            case '.':
            case '^':
            case '$':
            case '*':
            case '+':
            case '?':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '\\':
            case '|':
                escaped += '\\';
                escaped += c;
                break;
            default:
                escaped += c;
                break;
        }
    }
    return escaped;
}

HyperscanHook::HyperscanHook() : m_hsDatabase(nullptr), m_hsScratch(nullptr), m_hsReady(false) {}

HyperscanHook::~HyperscanHook() {
    if (m_hsScratch) hs_free_scratch(m_hsScratch);
    if (m_hsDatabase) hs_free_database(m_hsDatabase);
}

Maybe<void> HyperscanHook::prepare(const std::set<PMPattern> &patterns) {
    m_hsPatterns.clear();
    m_idToPattern.clear();    for (const auto &pat : patterns) {
        if (pat.empty()) continue; // Use pat.empty() instead of pat.pattern().empty()

        // Convert pattern data to string using the public interface
        std::string pattern_str(reinterpret_cast<const char*>(pat.data()), pat.size());

        // Escape regex special characters for literal matching
        std::string escaped_pattern = escapeRegexChars(pattern_str);

        m_hsPatterns.push_back(escaped_pattern);
        m_idToPattern.push_back(pat);
    }

    std::vector<const char*> c_patterns;
    std::vector<unsigned int> flags;
    std::vector<unsigned int> ids;

    for (size_t i = 0; i < m_hsPatterns.size(); ++i) {
        c_patterns.push_back(m_hsPatterns[i].c_str());
        flags.push_back(HS_FLAG_CASELESS); // adjust as needed
        ids.push_back((unsigned int)i);
    }    hs_compile_error_t *compile_err = nullptr;
    hs_error_t result = hs_compile_multi(c_patterns.data(), flags.data(), ids.data(),
                        (unsigned int)c_patterns.size(), HS_MODE_BLOCK, nullptr,
                        &m_hsDatabase, &compile_err);

    if (result != HS_SUCCESS) {
        std::string error_msg = "Failed to compile Hyperscan database";
        if (compile_err) {
            error_msg += ": ";
            error_msg += compile_err->message;
            hs_free_compile_error(compile_err);
        }
        return genError(error_msg);
    }if (hs_alloc_scratch(m_hsDatabase, &m_hsScratch) != HS_SUCCESS) {
        return genError("Failed to allocate Hyperscan scratch space");
    }

    m_hsReady = true;
    return Maybe<void>();
}

// TODO - No need for HS hook, scanning is done by WaapHyperscanEngine::scanSample()
std::set<PMPattern> HyperscanHook::scanBuf(const Buffer &buf) const {
    std::set<PMPattern> results;
    scanBufWithOffsetLambda(buf, [&results](uint, const PMPattern &pattern, bool) {
        results.insert(pattern);
    });
    return results;
}

std::set<std::pair<uint, uint>> HyperscanHook::scanBufWithOffset(const Buffer &buf) const {
    std::set<std::pair<uint, uint>> results;
    scanBufWithOffsetLambda(buf, [&results](uint endMatchOffset, const PMPattern &pattern, bool) {
        uint startOffset = endMatchOffset + 1 - pattern.size();
        results.insert(std::make_pair(startOffset, endMatchOffset));
    });
    return results;
}

void HyperscanHook::scanBufWithOffsetLambda(const Buffer &buf, I_PMScan::CBFunction cb) const {
    if (!m_hsReady) return;
    struct HyperScanContext {
        const HyperscanHook *self;
        const Buffer *buffer;
        I_PMScan::CBFunction cb;
    };
    auto onMatch = [](unsigned int id, unsigned long long, unsigned long long to, unsigned int,
                    void *ctx) -> int {
        HyperScanContext *hctx = (HyperScanContext*)ctx;
        const HyperscanHook *self = hctx->self;
        const PMPattern &pat = self->m_idToPattern[id];
        uint endMatchOffset = (uint)to - 1;
        hctx->cb(endMatchOffset, pat, false); // matchAll logic can be extended if needed
        return 0;
    };
    HyperScanContext ctx{this, &buf, cb};
    hs_scan(m_hsDatabase, (const char*)buf.data(), (unsigned int)buf.size(), 0, m_hsScratch, onMatch, &ctx);
}

#endif // USE_HYPERSCAN
