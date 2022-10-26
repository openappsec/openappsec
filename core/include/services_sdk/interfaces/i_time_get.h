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

#ifndef __I_TIME_GET_H__
#define __I_TIME_GET_H__

#include <string>
#include <chrono>

class I_TimeGet
{
public:
    virtual std::chrono::microseconds getMonotonicTime() = 0;
    virtual std::chrono::microseconds getWalltime() = 0;
    virtual std::string getWalltimeStr() = 0;
    virtual std::string getWalltimeStr(const std::chrono::microseconds &ms) = 0;
    virtual std::string getLocalTimeStr() = 0;

protected:
    virtual ~I_TimeGet() {}
};

#endif // __I_TIME_GET_H__
