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

#include "gradual_deployment.h"

#include <string>
#include <unordered_map>
#include <boost/algorithm/string.hpp>

#include "enum_range.h"
#include "connkey.h"

USE_DEBUG_FLAG(D_GRADUAL_DEPLOYMENT);

using namespace std;

class SetGradualDeploymentRanges : public ServerRest
{
public:
    void doCall() override
    {
        dbgFlow(D_GRADUAL_DEPLOYMENT) << "Set gradual policy API";

        auto maybe_type = convertServiceStrToAttachmentType(attachment_type.get());
        if (!maybe_type.ok()) {
            string error = "Failed to determine attachment type. Type: "
                + attachment_type.get()
                + ", error: "
                + maybe_type.getErr();
            dbgWarning(D_GRADUAL_DEPLOYMENT) << error;
            throw JsonError(error);
        }
        dbgTrace(D_GRADUAL_DEPLOYMENT)
            << "Setting gradual policy for attachment of type: "
            << attachment_type.get();

        auto i_gradual_deployment = Singleton::Consume<I_GradualDeployment>::from<GradualDeployment>();
        auto set_policy_res = i_gradual_deployment->setPolicy(maybe_type.unpackMove(), ip_ranges.get());
        if (!set_policy_res.ok()) throw JsonError(set_policy_res.getErr());

        return;
    }

private:
    C2S_PARAM(vector<string>, ip_ranges)
    C2S_PARAM(string, attachment_type)

    Maybe<I_GradualDeployment::AttachmentType>
    convertServiceStrToAttachmentType(string &type) {
        transform(type.begin(), type.end(), type.begin(), ::tolower);
        if (type == "http-manager") return I_GradualDeployment::AttachmentType::NGINX;
        if (type == "access-control") return I_GradualDeployment::AttachmentType::KERNEL;

        return genError("unknown attachment type");
    }
};

class GradualDeployment::Impl
        :
    Singleton::Provide<I_GradualDeployment>::From<GradualDeployment>
{
public:
    void
    init()
    {
        dbgFlow(D_GRADUAL_DEPLOYMENT) << "Initializing Gradual Deployment Manager";

        auto rest = Singleton::Consume<I_RestApi>::by<GradualDeployment>();
        rest->addRestCall<SetGradualDeploymentRanges>(RestAction::SET, "gradual-deployment-policy");

        dbgTrace(D_GRADUAL_DEPLOYMENT) << "Gradual Deployment Manager initialization is done successfully";
    }

    Maybe<void>
    setPolicy(I_GradualDeployment::AttachmentType type, const vector<string> &str_ip_ranges) override
    {
        auto maybe_policy = parseIpRanges(str_ip_ranges);
        if (!maybe_policy.ok()) {
            auto error = "Failed to set gradual deployment policy. Error: " + maybe_policy.getErr();
            dbgWarning(D_GRADUAL_DEPLOYMENT) << error;
            return genError(error);
        }

        ip_ranges_map[static_cast<int>(type)] = maybe_policy.unpackMove();
        return Maybe<void>();
    }

    vector<string>
    getPolicy(I_GradualDeployment::AttachmentType type) override
    {
        vector<string> res;
        for (const IPRange &range : ip_ranges_map[static_cast<int>(type)]) {
            // Range is validated on insertion
            res.push_back(convertIpRangeToStr(range).unpack());
        }
        return res;
    }

    vector<IPRange> &
    getParsedPolicy(I_GradualDeployment::AttachmentType type) override
    {
        return ip_ranges_map[static_cast<int>(type)];
    }

private:
    IpAddress
    ConvertToIpAddress(const IPAddr &addr) {
        IpAddress address;
        switch (addr.getType()) {
            case IPType::V4: {
                address.addr4_t = addr.getIPv4();
                address.ip_type = IP_VERSION_4;
                break;
            }
            case IPType::V6: {
                address.addr6_t = addr.getIPv6();
                address.ip_type = IP_VERSION_6;
                break;
            }
            default:
                dbgAssert(false) << "Unsupported IP type";
        }
        return address;
    }

    Maybe<IPRange>
    createRangeFromStr(const string &range)
    {
        vector<string> temp_params_list;
        boost::split(temp_params_list, range, boost::is_any_of("-"));

        if (temp_params_list.size() == 1) {
            Maybe<IPAddr> maybe_ip = IPAddr::createIPAddr(temp_params_list[0]);
            if (!maybe_ip.ok()) return genError("Could not create IP address, " + maybe_ip.getErr());
            IpAddress addr = move(ConvertToIpAddress(maybe_ip.unpackMove()));

            return move(IPRange{.start = addr, .end = addr});
        }

        if (temp_params_list.size() == 2) {
            Maybe<IPAddr> maybe_ip_min = IPAddr::createIPAddr(temp_params_list[0]);
            Maybe<IPAddr> maybe_ip_max = IPAddr::createIPAddr(temp_params_list[1]);
            if (!maybe_ip_min.ok()) return genError("Could not create IP address, " + maybe_ip_min.getErr());
            if (!maybe_ip_max.ok()) return genError("Could not create IP address, " + maybe_ip_max.getErr());

            IPAddr min_addr = maybe_ip_min.unpackMove();
            IPAddr max_addr = maybe_ip_max.unpackMove();
            if (min_addr > max_addr) return genError("Could not create ip range - start greater then end");

            IpAddress addr_min = move(ConvertToIpAddress(move(min_addr)));
            IpAddress addr_max = move(ConvertToIpAddress(move(max_addr)));
            if (addr_max.ip_type != addr_min.ip_type) return genError("Range IP's type does not match");

            return move(IPRange{.start = move(addr_min), .end = move(addr_max)});
        }

        return genError("Illegal range received: " + range);
    }

    Maybe<vector<IPRange>>
    parseIpRanges(const vector<string> &str_ip_ranges)
    {
        vector<IPRange> ip_ranges;
        for (const string &range : str_ip_ranges) {
            Maybe<IPRange> ip_range = createRangeFromStr(range);
            if (!ip_range.ok()) {
                return genError("Failed to parse gradual deployment IP range: " + ip_range.getErr());
            }

            ip_ranges.push_back(ip_range.unpackMove());
        }
        return move(ip_ranges);
    }

    Maybe<string>
    convertIpRangeToStr(const IPRange &range)
    {
        if (range.start.ip_type != IP_VERSION_4 && range.start.ip_type != IP_VERSION_6) {
            return genError("Unknown IP type received: " + range.start.ip_type);
        }

        size_t len;
        int type;
        const void *in_addr_min;
        const void *in_addr_max;

        if (range.start.ip_type == IP_VERSION_4) {
            len = INET_ADDRSTRLEN;
            type = AF_INET;
            in_addr_min = &range.start.ip.ipv4;
            in_addr_max = &range.end.ip.ipv4;
        } else {
            len = INET6_ADDRSTRLEN;
            type = AF_INET6;
            in_addr_min = &range.start.ip.ipv6;
            in_addr_max = &range.end.ip.ipv6;
        }

        char str_min[len];
        inet_ntop(type, in_addr_min, str_min, len);
        char str_max[len];
        inet_ntop(type, in_addr_max, str_max, len);

        string start(str_min, strnlen(str_min, len));
        string end(str_max, strnlen(str_max, len));

        return start + "-" + end;
    }

    unordered_map<size_t, vector<IPRange>> ip_ranges_map;
};

GradualDeployment::GradualDeployment() : Component("GradualDeployment"), pimpl(make_unique<Impl>()) {}

GradualDeployment::~GradualDeployment() {}

void GradualDeployment::init() { pimpl->init(); }
