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

#include "instance_awareness.h"

#include <algorithm>
#include <ctype.h>

#include "debug.h"
#include "config.h"
#include "common.h"

using namespace std;

USE_DEBUG_FLAG(D_CONFIG);

class InstanceAwareness::Impl : public Singleton::Provide<I_InstanceAwareness>::From<InstanceAwareness>
{
public:
    Maybe<string>
    getInstanceID() override
    {
        Maybe<string> instance_id = checkIfValueIsConfigured("id");
        if (instance_id.ok()) return instance_id;

        return genError("Instance Awareness isn't active, Error: " + instance_id.getErr());
    }

    Maybe<string>
    getFamilyID() override
    {
        Maybe<string> family_id = checkIfValueIsConfigured("family");
        if (family_id.ok()) return family_id;

        return genError("Family ID isn't active, Error: " + family_id.getErr());
    }

    Maybe<string>
    getUniqueID() override
    {
        Maybe<string> instance_id(getInstanceID());
        if (!instance_id.ok()) return genError("Can't get instance ID, Error: " + instance_id.getErr());

        Maybe<string> family_id(getFamilyID());
        if (!family_id.ok()) return *instance_id;

        return *family_id + "_" + *instance_id;
    }

    string getUniqueID(const string &val) override { return getIDWithDefault(getUniqueID(), val); }
    string getFamilyID(const string &val) override { return getIDWithDefault(getFamilyID(), val); }
    string getInstanceID(const string &val) override { return getIDWithDefault(getInstanceID(), val); }

private:
    string
    getIDWithDefault(const Maybe<string> &id, const string &default_val)
    {
        return id.ok() ? *id : default_val;
    }

    Maybe<string>
    checkIfValueIsConfigured(const string &flag)
    {
        string flag_val = getConfigurationFlag(flag);

        if (find_if(flag_val.begin(), flag_val.end(), isBadChar) != flag_val.end()) {
            dbgError(D_CONFIG) << "Illegal flag: " << flag << "=" << flag_val;
            return genError("Illegal flag: " + flag);
        }

        if (flag_val == "") {
            dbgDebug(D_CONFIG) << "The flag is not configured: " << flag;
            return genError("Flag not found");
        }
        return flag_val;
    }

    static bool isBadChar(char ch) { return !isalnum(ch) && ch != '-'; }
};

InstanceAwareness::InstanceAwareness() : Component("InstanceAwareness"), pimpl(make_unique<Impl>()) {}

InstanceAwareness::~InstanceAwareness() {}
