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

#ifndef __I_IGNORE_SOURCES_H__
#define __I_IGNORE_SOURCES_H__
#include <vector>
#include <string>

class I_IgnoreSources
{
public:
    virtual std::vector<std::string>* getSourcesToIgnore() = 0;
    virtual bool ready() = 0;
};

#endif
