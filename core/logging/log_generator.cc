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

#include "log_generator.h"

using namespace std;

extern const string unnamed_service;

LogGen::~LogGen()
{
    try {
        if (send_log) Singleton::Consume<I_Logging>::by<LogGen>()->sendLog(log);
    } catch (...) {
    }
}

LogGen &
LogGen::operator<<(const LogField &field)
{
    log << field;
    return *this;
}

void
LogGen::addToOrigin(const LogField &field)
{
    log.addToOrigin(field);
}

void
LogGen::serialize(cereal::JSONOutputArchive &ar) const
{
    log.serialize(ar);
}

chrono::microseconds
LogGen::getCurrentTime() const
{
    return Singleton::Consume<I_TimeGet>::by<LogGen>()->getWalltime();
}

ReportIS::AudienceTeam
LogGen::getAudienceTeam() const
{
    if (Singleton::exists<I_Environment>()) {
        auto team = Singleton::Consume<I_Environment>::by<LogGen>()->get<ReportIS::AudienceTeam>("Audience Team");
        if (team.ok()) return *team;
    }
    return ReportIS::AudienceTeam::NONE;
}

string
LogGen::getLogInsteadOfSending()
{
    send_log = false;
    stringstream output;
    {
        cereal::JSONOutputArchive ar(output);
        log.serialize(ar);
    }
    return output.str();
}

void
LogGen::loadBaseLogFields()
{
    size_t curr_index = Singleton::Consume<I_Logging>::by<LogGen>()->getCurrentLogId();
    log.setIndex(curr_index);
    log << LogField("logIndex", curr_index);

    if (!Singleton::exists<I_Environment>()) return;
    auto env = Singleton::Consume<I_Environment>::by<LogGen>();

    for (auto &string_by_key : env->getAllStrings(EnvKeyAttr::LogSection::SOURCE)) {
        log.addToOrigin(LogField(string_by_key.first, string_by_key.second));
    }

    for (auto &uint64_by_key : env->getAllUints(EnvKeyAttr::LogSection::SOURCE)) {
        log.addToOrigin(LogField(uint64_by_key.first, uint64_by_key.second));
    }

    for (auto &bool_by_key : env->getAllBools(EnvKeyAttr::LogSection::SOURCE)) {
        log.addToOrigin(LogField(bool_by_key.first, bool_by_key.second));
    }

    for (auto &string_by_key : env->getAllStrings(EnvKeyAttr::LogSection::DATA)) {
        log << LogField(string_by_key.first, string_by_key.second);
    }

    for (auto &uint64_by_key : env->getAllUints(EnvKeyAttr::LogSection::DATA)) {
        log << LogField(uint64_by_key.first, uint64_by_key.second);
    }

    for (auto &bool_by_key : env->getAllBools(EnvKeyAttr::LogSection::DATA)) {
        log << LogField(bool_by_key.first, bool_by_key.second);
    }

    for (auto &string_by_key : env->getAllStrings(EnvKeyAttr::LogSection::SOURCEANDDATA)) {
        log.addToOrigin(LogField(string_by_key.first, string_by_key.second));
        log << LogField(string_by_key.first, string_by_key.second);
    }

    for (auto &uint64_by_key : env->getAllUints(EnvKeyAttr::LogSection::SOURCEANDDATA)) {
        log.addToOrigin(LogField(uint64_by_key.first, uint64_by_key.second));
        log << LogField(uint64_by_key.first, uint64_by_key.second);
    }

    for (auto &bool_by_key : env->getAllBools(EnvKeyAttr::LogSection::SOURCEANDDATA)) {
        log.addToOrigin(LogField(bool_by_key.first, bool_by_key.second));
        log << LogField(bool_by_key.first, bool_by_key.second);
    }

    log.getMarkers() = env->getAllStrings(EnvKeyAttr::LogSection::MARKER);
}
