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

#ifndef __REPORT_LOG_REST_H__
#define __REPORT_LOG_REST_H__

#include <vector>

#include "rest.h"
#include "report/report.h"

USE_DEBUG_FLAG(D_INFRA);

class LogRest
{
public:
    LogRest(const Report &_log) : log(_log) {}
    LogRest(Report &&_log) : log(std::move(_log)) {}

    Maybe<std::string>
    genJson() const
    {
        std::stringstream os;
        {
            cereal::JSONOutputArchive ar(os);
            try {
                save(ar);
            } catch (...) {
                return genError("Failed to generate JSON from log");
            }
        }
        return os.str();
    }

    void
    save(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("log", log));
    }

private:
    Report log;
};

class LogBulkRest
{
public:
    LogBulkRest() {}

    LogBulkRest(uint size)
    {
        logs.reserve(size);
    }

    void
    save(cereal::JSONOutputArchive &ar) const
    {
        dbgTrace(D_INFRA) << "Creating bulk of logs. Expected logs to be sent: " << logs.size();

        ar.makeArray();

        uint index = 0;
        for (auto &log : logs) {
            ar.startNode();
            // fogs' id starts from 1
            ar(cereal::make_nvp("id", ++index));
            ar(cereal::make_nvp("log", log));
            ar.finishNode();
        }
    }

    Maybe<std::string>
    genJson() const
    {
        std::stringstream os;
        {
            cereal::JSONOutputArchive ar(os);
            try {
                ar(cereal::make_nvp("logs", *this));
            } catch (...) {
                return genError("Failed to generate JSON from log");
            }
        }
        return os.str();
    }

    bool isFull() const { return logs.size() == logs.capacity(); }

    void push(Report &&log) { logs.emplace_back(std::move(log)); }
    void push(const Report &log) { logs.emplace_back(log); }

    std::vector<Report>::iterator erase(const std::vector<Report>::iterator &it) { return logs.erase(it); }

    uint size() const { return logs.size(); }
    std::vector<Report>::const_iterator begin() const { return logs.begin(); }
    std::vector<Report>::const_iterator end()   const { return logs.end();   }

    std::vector<Report>::iterator begin() { return logs.begin(); }
    std::vector<Report>::iterator end()   { return logs.end(); }

private:
    std::vector<Report> logs;
};

#endif // __REPORT_LOG_REST_H__
