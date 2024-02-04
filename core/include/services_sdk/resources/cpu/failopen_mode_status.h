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

#ifndef __FAILOPEN_MODE_STATUS_H__
#define __FAILOPEN_MODE_STATUS_H__

#include "event.h"

class FailopenModeEvent : public Event<FailopenModeEvent>
{
public:
    FailopenModeEvent(bool _failopen_status = false)
            :
        failopen_mode_status(_failopen_status)
    {
    }

    void
    setFailopenMode(bool status)
    {
        failopen_mode_status = status;
    }

    bool
    getFailopenMode() const
    {
        return failopen_mode_status;
    }

private:
    bool failopen_mode_status;
};

#endif // __FAILOPEN_MODE_STATUS_H__
