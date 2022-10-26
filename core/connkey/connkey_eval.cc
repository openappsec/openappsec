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

#include "connkey.h"
#include "environment/evaluator_templates.h"

#include <boost/lexical_cast.hpp>

using namespace std;
using namespace EnvironmentHelper;

class ConstantPort : public Constant<uint16_t>
{
public:
    ConstantPort(const vector<string> &params)
            :
        Constant<uint16_t>(
            [] (const string & str) {
                uint16_t value = 0;
                try {
                    value = boost::lexical_cast<uint16_t>(str);
                } catch (boost::bad_lexical_cast const&) {
                    reportWrongParamType(getName(), str, "Not a port number");
                }
                return value;
            },
            params
        ) {}

    static string getName() { return Constant<uint16_t>::getName() + "Port"; }
};

class ConstantIP : public Constant<IPAddr>
{
public:
    ConstantIP(const vector<string> &params)
            :
        Constant<IPAddr>(
            [] (const string & str) {
                auto addr = IPAddr::createIPAddr(str);
                if (!addr.ok()) reportWrongParamType(getName(), str, "Not an IP address");
                return *addr;
            },
            params
        ) {}

    static string getName() { return Constant<IPAddr>::getName() + "IP"; }
};

class ConstantProtocol : public Constant<IPProto>
{
public:
    ConstantProtocol(const vector<string> &params)
            :
        Constant<IPProto>(
            [] (const string &str) {
                uint16_t value = 0;
                for (auto &ch : str) {
                    if (ch < '0' || ch > '9') reportWrongParamType(getName(), str, "Not a protocol ID character");
                    value = value * 10 + (ch - '0');
                    if (256 <= value) reportWrongParamType(getName(), str, "Not a protocol ID number");
                }
                return static_cast<IPProto>(value);
            },
            params
        ) {}

    static string getName() { return Constant<IPProto>::getName() + "Protocol"; }
};

class EqualPort : public Equal<uint16_t>
{
public:
    EqualPort(const vector<string> &params) : Equal<uint16_t>(params) {}
    static string getName() { return Equal<uint16_t>::getName() + "Port"; }
};

class EqualIP : public Equal<IPAddr>
{
public:
    EqualIP(const vector<string> &params) : Equal<IPAddr>(params) {}
    static string getName() { return Equal<IPAddr>::getName() + "IP"; }
};

class EqualProtocol : public Equal<IPProto>
{
public:
    EqualProtocol(const vector<string> &params) : Equal<IPProto>(params) {}
    static string getName() { return Equal<IPProto>::getName() + "Protocol"; }
};

class DPort : public Invoker<uint16_t, ConnKey>
{
public:
    DPort(const vector<string> &params)
            :
        Invoker<uint16_t, ConnKey>([] (const ConnKey &key) { return key.getDPort(); }, params) {}
    static string getName() { return Invoker<uint16_t, ConnKey>::getName() + "DPort"; }
};

class SPort : public Invoker<uint16_t, ConnKey>
{
public:
    SPort(const vector<string> &params)
            :
        Invoker<uint16_t, ConnKey>([] (const ConnKey &key) { return key.getSPort(); }, params) {}

    static string getName() { return Invoker<uint16_t, ConnKey>::getName() + "SPort"; }
};

class Dst : public Invoker<IPAddr, ConnKey>
{
public:
    Dst(const vector<string> &params)
            :
        Invoker<IPAddr, ConnKey>([] (const ConnKey &key) { return key.getDst(); }, params) {}

    static string getName() { return Invoker<IPAddr, ConnKey>::getName() + "Dst"; }
};

class Src : public Invoker<IPAddr, ConnKey>
{
public:
    Src(const vector<string> &params)
            :
        Invoker<IPAddr, ConnKey>([] (const ConnKey &key) { return key.getSrc(); }, params) {}

    static string getName() { return Invoker<IPAddr, ConnKey>::getName() + "Src"; }
};

class Protocol : public Invoker<IPProto, ConnKey>
{
public:
    Protocol(const vector<string> &params)
            :
        Invoker<IPProto, ConnKey>([] (const ConnKey &key) { return key.getProto(); }, params) {}

    static string getName() { return Invoker<IPProto, ConnKey>::getName() + "Protocol"; }
};

void
ConnKey::preload()
{
    addMatcher<ConstantPort>();
    addMatcher<ConstantIP>();
    addMatcher<ConstantProtocol>();

    addMatcher<EqualPort>();
    addMatcher<EqualIP>();
    addMatcher<EqualProtocol>();

    addMatcher<DPort>();
    addMatcher<SPort>();
    addMatcher<Dst>();
    addMatcher<Src>();
    addMatcher<Protocol>();
}
