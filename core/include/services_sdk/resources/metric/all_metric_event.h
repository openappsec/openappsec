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

#ifndef __ALL_METRIC_EVENT_H__
#define __ALL_METRIC_EVENT_H__

#include "event.h"

class AllMetricEvent : public Event<AllMetricEvent, std::string>
{
public:
    AllMetricEvent(bool _with_reset = false) : with_reset(_with_reset) {}

    void
    setReset(bool value)
    {
        with_reset = value;
    }

    bool
    getReset() const
    {
        return with_reset;
    }

private:
    bool with_reset;
};

#endif // __ALL_METRIC_EVENT_H__
