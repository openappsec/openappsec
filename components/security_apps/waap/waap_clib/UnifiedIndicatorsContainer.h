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

#pragma once

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <iostream>
#include <cereal/cereal.hpp>
#include <cereal/archives/json.hpp>
#include "i_serialize.h"
// #include "custom_serialization.h"

// Indicator type enumeration for type safety and compactness
enum class IndicatorType : uint8_t {
    KEYWORD = 0,
    TYPE = 1
};

typedef std::unordered_set<std::string*> SourcesSet;
typedef std::unordered_map<std::string*, SourcesSet> FilterData;

// Proposed name for `Filters`: KeyLog (represents the per-key section under "logger")
// Keeping class name as Filters to minimize changes; can be renamed in a follow-up.
class Filters {
public:
    Filters() = default;
    ~Filters() = default;

    // Const overload for cereal serialization
    template<class Archive>
    void serialize(Archive& ar) const {
        std::vector<std::string> totalSourcesVec;
        std::unordered_map<std::string, std::vector<std::string>> indicatorsMap, typesMap;

        for (auto p : totalSources) {
            if (p) totalSourcesVec.push_back(*p);
        }
        for (const auto& kv : indicators) {
            std::string key = kv.first ? *kv.first : std::string();
            std::vector<std::string> sources;
            for (auto p : kv.second) {
                if (p) sources.push_back(*p);
            }
            indicatorsMap[key] = sources;
        }
        for (const auto& kv : types) {
            std::string key = kv.first ? *kv.first : std::string();
            std::vector<std::string> sources;
            for (auto p : kv.second) {
                if (p) sources.push_back(*p);
            }
            typesMap[key] = sources;
        }

        ar(
            cereal::make_nvp("totalSources", totalSourcesVec),
            cereal::make_nvp("indicators", indicatorsMap),
            cereal::make_nvp("types", typesMap)
        );
    }

    // Accessors for container implementation
    FilterData & getIndicators() { return indicators; }
    FilterData & getTypes() { return types; }
    const FilterData & getIndicators() const { return indicators; }
    const FilterData & getTypes() const { return types; }

    // Per-key total sources (union of sources from indicators and types)
    SourcesSet & getTotalSources() { return totalSources; }
    const SourcesSet & getTotalSources() const { return totalSources; }

private:
    FilterData indicators;
    FilterData types;
    SourcesSet totalSources;
};

// Unified indicators container with string interning and memory optimization
class UnifiedIndicatorsContainer {
public:
    // Batch entry input
    struct Entry {
        std::string key;
        std::string sourceId;
        bool isTrusted = false;
        std::vector<std::string> indicators; // values treated as KEYWORD
        std::vector<std::string> types;      // values treated as TYPE
    };
    void addEntry(const Entry& entry);

    // Check if an indicator exists
    bool hasIndicator(const std::string& key, const std::string& value, IndicatorType type) const;

    // Get all sources for a specific indicator
    std::unordered_set<std::string> getSources(const std::string& key,
                                                const std::string& value,
                                                IndicatorType type) const;

    // Statistics and metrics
    size_t getIndicatorCount() const;
    size_t getKeyCount() const;
    size_t getValuePoolSize() const;
    // Returns true if the given source string is marked as trusted (appears in the global trustedSources set)
    bool isTrustedSource(const std::string &source) const;

    // Container management
    void clear();

    // Serialization for cross-agent compatibility
    // void serialize(std::ostream& stream) const;
    template<class Archive>
    void serialize(Archive& ar) const {
        // trustedSources as array
        std::vector<std::string> trusted_srcs;
        for (auto p : trustedSources) {
            if (p) trusted_srcs.push_back(*p);
        }
        ar.setNextName("trustedSources");
        ar.startNode();
        cereal::size_type n_trusted = static_cast<cereal::size_type>(trusted_srcs.size());
        ar(cereal::make_size_tag(n_trusted));
        for (const auto &s : trusted_srcs) ar(s);
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
    void serialize(std::ostream &stream) const;
    void deserialize(std::istream& stream);

private:
    // Single indicator add
    void addIndicator(const std::string& key, const std::string& value,
                        IndicatorType type, const std::string& source);

    // String interning pool for values
    std::unordered_set<std::string> valuePool;

    // String interning pool for sources
    std::unordered_set<std::string> sourcesPool;

    // Main storage: key -> Filters
    std::unordered_map<std::string, Filters> filtersDataPerKey;

    // Global set of trusted sources
    std::unordered_set<const std::string*> trustedSources;

    // Helper methods
    const std::string* internValue(const std::string& value);
    const std::string* internSource(const std::string& source);
};
// UnifiedIndicatorsLogPost for REST, compatible with cereal and messaging
class UnifiedIndicatorsLogPost : public RestGetFile {
public:
    UnifiedIndicatorsLogPost(std::shared_ptr<UnifiedIndicatorsContainer> container_ptr)
    {
        unifiedIndicators = std::move(*container_ptr);
    }

private:
    C2S_PARAM(UnifiedIndicatorsContainer, unifiedIndicators);
};
