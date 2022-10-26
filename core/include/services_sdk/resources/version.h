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

#ifndef __VERSION_H__
#define __VERSION_H__

#include <string>

#include "i_rest_api.h"
#include "i_environment.h"
#include "singleton.h"

// get the current firewall version
class Version : Singleton::Consume<I_RestApi>, Singleton::Consume<I_Environment>
{
public:
    static void preload() {}

    static void init();
    static void fini() {}

    static std::string getName() { return "Version"; }

    static std::string get();
    static bool isPublic();
    static std::string getID();
    static std::string getUser();
    static std::string getTimestamp();
    static std::string getVerPrefix();
    static std::string getFullVersion();
    static std::string getBranch();
};

#endif // __VERSION_H__
