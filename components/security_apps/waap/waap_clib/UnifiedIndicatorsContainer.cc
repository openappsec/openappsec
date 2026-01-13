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

#include "UnifiedIndicatorsContainer.h"

#include <cereal/archives/json.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>
#include <algorithm>

using std::string;
using std::unordered_map;
using std::unordered_set;
using std::ostream;
using std::istream;

// -------------------------------
// Interning helpers
// -------------------------------
const std::string*
UnifiedIndicatorsContainer::internValue(const std::string &value)
{
    auto it = valuePool.find(value);
    if (it == valuePool.end()) it = valuePool.insert(value).first;
    return &(*it);
}

const std::string*
UnifiedIndicatorsContainer::internSource(const std::string &source)
{
    auto it = sourcesPool.find(source);
    if (it == sourcesPool.end()) it = sourcesPool.insert(source).first;
    return &(*it);
}

// -------------------------------
// Public API
// -------------------------------
void
UnifiedIndicatorsContainer::addIndicator(
    const std::string &key,
    const std::string &value,
    IndicatorType type,
    const std::string &source)
{
    auto &filters = filtersDataPerKey[key];

    const std::string *valPtr = internValue(value);
    const std::string *srcPtr = internSource(source);

    FilterData &bucket = (type == IndicatorType::KEYWORD)
        ? filters.getIndicators()
        : filters.getTypes();

    auto &srcSet = bucket[const_cast<std::string*>(valPtr)];
    srcSet.insert(const_cast<std::string*>(srcPtr));

    // Update per-key total sources union
    filters.getTotalSources().insert(const_cast<std::string*>(srcPtr));
}

void UnifiedIndicatorsContainer::addEntry(const Entry &entry)
{
    const std::string *srcPtr = internSource(entry.sourceId);
    if (entry.isTrusted && srcPtr) {
        trustedSources.insert(srcPtr);
    }
    for (const auto &val : entry.indicators) {
        addIndicator(entry.key, val, IndicatorType::KEYWORD, entry.sourceId);
    }
    for (const auto &val : entry.types) {
        addIndicator(entry.key, val, IndicatorType::TYPE, entry.sourceId);
    }
}

bool
UnifiedIndicatorsContainer::hasIndicator(
    const std::string &key,
    const std::string &value,
    IndicatorType type) const
{
    auto keyIt = filtersDataPerKey.find(key);
    if (keyIt == filtersDataPerKey.end()) return false;

    const Filters &filters = keyIt->second;
    const FilterData &bucket = (type == IndicatorType::KEYWORD)
        ? filters.getIndicators()
        : filters.getTypes();

    auto valIt = valuePool.find(value);
    if (valIt == valuePool.end()) return false;

    auto it = bucket.find(const_cast<std::string*>(&(*valIt)));
    return it != bucket.end();
}

std::unordered_set<std::string>
UnifiedIndicatorsContainer::getSources(
    const std::string &key,
    const std::string &value,
    IndicatorType type) const
{
    std::unordered_set<std::string> out;

    auto keyIt = filtersDataPerKey.find(key);
    if (keyIt == filtersDataPerKey.end()) return out;

    const Filters &filters = keyIt->second;
    const FilterData &bucket = (type == IndicatorType::KEYWORD)
        ? filters.getIndicators()
        : filters.getTypes();

    auto valIt = valuePool.find(value);
    if (valIt == valuePool.end()) return out;

    auto it = bucket.find(const_cast<std::string*>(&(*valIt)));
    if (it == bucket.end()) return out;

    for (auto p : it->second) if (p) out.insert(*p);
    return out;
}

size_t
UnifiedIndicatorsContainer::getIndicatorCount() const
{
    size_t count = 0;
    for (const auto &k : filtersDataPerKey) {
        count += k.second.getIndicators().size();
        count += k.second.getTypes().size();
    }
    return count;
}

size_t
UnifiedIndicatorsContainer::getKeyCount() const
{
    return filtersDataPerKey.size();
}

size_t
UnifiedIndicatorsContainer::getValuePoolSize() const
{
    return valuePool.size();
}

void
UnifiedIndicatorsContainer::clear()
{
    filtersDataPerKey.clear();
    valuePool.clear();
    sourcesPool.clear();
    trustedSources.clear();
}

// -------------------------------
// Serialization
// -------------------------------
void
UnifiedIndicatorsContainer::serialize(std::ostream &stream) const
{
    cereal::JSONOutputArchive ar(stream);

    // Write trustedSources as a named array under the root object (global trusted only)
    ar.setNextName("trustedSources");
    ar.startNode();
    cereal::size_type n_trusted = static_cast<cereal::size_type>(trustedSources.size());
    ar(cereal::make_size_tag(n_trusted));
    for (auto p : trustedSources) ar(p ? *p : std::string());
    ar.finishNode();

    // logger: object of keys -> { totalSources: [...], indicators: {...}, types: {...} }
    ar.setNextName("logger");
    ar.startNode();
    for (const auto &k : filtersDataPerKey) {
        ar.setNextName(k.first.c_str());
        ar.startNode();

        // totalSources section (union per key)
        ar.setNextName("totalSources");
        ar.startNode();
        const auto &ts = k.second.getTotalSources();
        cereal::size_type ts_sz = static_cast<cereal::size_type>(ts.size());
        ar(cereal::make_size_tag(ts_sz));
        for (auto p : ts) ar(p ? *p : std::string());
        ar.finishNode();

        // indicators section
        ar.setNextName("indicators");
        ar.startNode();
        for (const auto &kv : k.second.getIndicators()) {
            const std::string *val = kv.first;
            ar.setNextName(val ? val->c_str() : "");
            ar.startNode();
            cereal::size_type sz = static_cast<cereal::size_type>(kv.second.size());
            ar(cereal::make_size_tag(sz));
            for (auto p : kv.second) ar(p ? *p : std::string());
            ar.finishNode(); // end value array
        }
        ar.finishNode(); // end indicators

        // types section
        ar.setNextName("types");
        ar.startNode();
        for (const auto &kv : k.second.getTypes()) {
            const std::string *val = kv.first;
            ar.setNextName(val ? val->c_str() : "");
            ar.startNode();
            cereal::size_type sz = static_cast<cereal::size_type>(kv.second.size());
            ar(cereal::make_size_tag(sz));
            for (auto p : kv.second) ar(p ? *p : std::string());
            ar.finishNode(); // end value array
        }
        ar.finishNode(); // end types

        ar.finishNode(); // end key object
    }
    ar.finishNode(); // end logger
}

void
UnifiedIndicatorsContainer::deserialize(std::istream &stream)
{
    cereal::JSONInputArchive ar(stream);
    clear();

    // trustedSources (optional) as a named array
    try {
        ar.setNextName("trustedSources");
        ar.startNode();
        cereal::size_type n = 0;
        ar(cereal::make_size_tag(n));
        for (cereal::size_type i = 0; i < n; ++i) {
            std::string s; ar(s);
            const std::string *p = internSource(s);
            trustedSources.insert(p);
        }
        ar.finishNode();
    } catch (...) {
        // Field may be absent
    }

    // logger
    try {
        ar.setNextName("logger");
        ar.startNode();
        while (true) {
            const auto node_name = ar.getNodeName();
            if (!node_name) break;

            std::string key = node_name;
            ar.startNode(); // enter key object

            // totalSources (optional)
            try {
                ar.setNextName("totalSources");
                ar.startNode();
                cereal::size_type ts_sz = 0;
                ar(cereal::make_size_tag(ts_sz));
                auto &ts = filtersDataPerKey[key].getTotalSources();
                for (cereal::size_type i = 0; i < ts_sz; ++i) {
                    std::string s; ar(s);
                    const std::string *p = internSource(s);
                    ts.insert(const_cast<std::string*>(p));
                }
                ar.finishNode();
            } catch (...) {
                // no totalSources
            }

            // indicators
            try {
                ar.setNextName("indicators");
                ar.startNode();
                while (true) {
                    const auto val_name = ar.getNodeName();
                    if (!val_name) break;
                    std::string value = val_name;
                    ar.startNode();
                    cereal::size_type sz = 0;
                    ar(cereal::make_size_tag(sz));
                    for (cereal::size_type i = 0; i < sz; ++i) {
                        std::string src; ar(src);
                        addIndicator(key, value, IndicatorType::KEYWORD, src);
                    }
                    ar.finishNode(); // end value array
                }
                ar.finishNode();
            } catch (...) {
                // no indicators
            }

            // types
            try {
                ar.setNextName("types");
                ar.startNode();
                while (true) {
                    const auto val_name = ar.getNodeName();
                    if (!val_name) break;
                    std::string value = val_name;
                    ar.startNode();
                    cereal::size_type sz = 0;
                    ar(cereal::make_size_tag(sz));
                    for (cereal::size_type i = 0; i < sz; ++i) {
                        std::string src; ar(src);
                        addIndicator(key, value, IndicatorType::TYPE, src);
                    }
                    ar.finishNode(); // end value array
                }
                ar.finishNode();
            } catch (...) {
                // no types
            }

            ar.finishNode(); // finish key object
        }
        ar.finishNode(); // finish logger
    } catch (...) {
        // Field may be absent
    }
}

bool UnifiedIndicatorsContainer::isTrustedSource(const std::string &source) const {
    // Linear check via interning: attempt to find an interned pointer matching source
    // We maintain sourcesPool mapping actual std::string storage, so compare by value.
    for (const auto &p : trustedSources) {
        if (p && *p == source) return true;
    }
    return false;
}
