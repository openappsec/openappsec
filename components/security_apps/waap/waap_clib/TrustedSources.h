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
#include <vector>
#include <map>
#include <cereal/types/vector.hpp>
#include <cereal/types/map.hpp>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

// used to load trusted sources policy
namespace Waap {
    namespace TrustedSources {

        enum TrustedSourceType {
            UNKNOWN,
            SOURCE_IP,
            X_FORWARDED_FOR,
            COOKIE_OAUTH2_PROXY,
            SM_USER
        };

        class Identifer
        {
        public:
            Identifer();

            template <typename _A>
            void serialize(_A& ar) {
                std::string temp;
                ar(cereal::make_nvp("sourceIdentifier", temp),
                    cereal::make_nvp("value", value));
                identitySource = convertSourceIdentifierToEnum(temp);
                if (identitySource == UNKNOWN)
                {
                    dbgDebug(D_WAAP) << "loaded " << temp << " from policy is not a recognized source identifier";
                }
            }

            static TrustedSourceType convertSourceIdentifierToEnum(std::string identifierType);

            TrustedSourceType identitySource;
            std::string value;
        };

        class SourcesIdentifers
        {
        public:
            template <typename _A>
            void serialize(_A& ar) {
                std::vector<Identifer> identifiers;
                ar(cereal::make_nvp("sourcesIdentifiers", identifiers),
                    cereal::make_nvp("numOfSources", m_minSources));
                for (auto identifier : identifiers)
                {
                    if (identifier.identitySource != UNKNOWN)
                    {
                        m_identifiersMap[identifier.identitySource].push_back(identifier.value);
                        m_trustedTypes.insert(identifier.identitySource);
                    }
                }
            }

            bool isCidrMatch(const std::string &source, const TrustedSourceType &type) const;
            bool isRegexMatch(const std::string &source, const TrustedSourceType& type) const;
            size_t getNumOfSources() const;
            const std::set<TrustedSourceType>& getTrustedTypes();

            inline bool operator!=(const SourcesIdentifers& other) const;
        private:
            std::map<TrustedSourceType, std::vector<std::string>> m_identifiersMap;
            std::set<TrustedSourceType> m_trustedTypes;
            size_t m_minSources;
        };

        class TrustedSourcesParameter
        {
        public:
            template <typename _A>
            TrustedSourcesParameter(_A& ar) {
                ar(cereal::make_nvp("trustedSources", m_identifiers));
            }

            TrustedSourcesParameter();

            template <class Archive>
            void serialize(Archive& ar) {
                ar(cereal::make_nvp("trustedSources", m_identifiers));
            }
            bool isSourceTrusted(std::string source, TrustedSourceType srcType);
            size_t getNumOfSources();
            std::set<TrustedSourceType> getTrustedTypes();
            bool operator==(const TrustedSourcesParameter &other) const;
            bool operator!=(const TrustedSourcesParameter& other) const;
        private:
            std::vector<SourcesIdentifers> m_identifiers;
        };
    }
}
