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

#ifndef __REPUTATION_FEATURES_EVENTS_H__
#define __REPUTATION_FEATURES_EVENTS_H__

#include "event.h"
#include "http_inspection_events.h"

using ResponseCode = uint16_t;
class ReputationFeaturesEntry;

class TearDownEvent : public Event<TearDownEvent>
{
public:
    TearDownEvent(ReputationFeaturesEntry *pEntry) : m_pEntry(pEntry)
    {

    }

    ReputationFeaturesEntry *
    getEntry() const
    {
        return m_pEntry;
    }

private:
    ReputationFeaturesEntry *m_pEntry;
};

class IdentifiersEvent : public Event<IdentifiersEvent>
{
public:
    IdentifiersEvent(const std::string &sourceId, const std::string &assetId)
            :
        m_sourceId(sourceId),
        m_assetId(assetId)
    { }

    const std::string &
    getSourceId() const
    {
        return m_sourceId;
    }

    const std::string &
    getAssetId() const
    {
        return m_assetId;
    }

private:
    const std::string m_sourceId;
    const std::string m_assetId;
};

class DetectionEvent : public Event<DetectionEvent>
{
public:
    DetectionEvent(const std::string &location, const std::vector<std::string> &indicators)
            :
        m_location(location),
        m_indicators(indicators)
    { }

    // LCOV_EXCL_START - sync functions, can only be tested once the sync module exists

    DetectionEvent() {}
    template <typename T>
    void
    serialize(T &ar)
    {
        ar(m_location, m_indicators);
    }

    // LCOV_EXCL_STOP


    const std::string&
    getLocation() const
    {
        return m_location;
    }

private:
    std::string m_location;
    std::vector<std::string> m_indicators;
};

#endif // __REPUTATION_FEATURES_EVENTS_H__
