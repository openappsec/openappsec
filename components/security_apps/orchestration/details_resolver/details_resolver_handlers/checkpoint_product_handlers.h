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

#ifndef __CHECKPOINT_PRODUCT_HANDLERS_H__
#define __CHECKPOINT_PRODUCT_HANDLERS_H__

#include <algorithm>
#include <boost/regex.hpp>

#if defined(gaia)

Maybe<string>
checkHasSupportedBlade(const string &command_output)
{
    string supportedBlades[3] = {"identityServer", "vpn", "cvpn"};
    for(const string &blade : supportedBlades) {
        if (command_output.find(blade) != string::npos) {
            return string("true");
        }
    }

    return genError("Current host does not have IDA capability");
}

Maybe<string>
checkSamlPortal(const string &command_output)
{
    if (command_output.find("Portal is running") != string::npos) {
        return string("true");
    }

    return genError("Current host does not have SAML Portal configured");
}

Maybe<string>
getIDAGaia(const string &command_output)
{
    return string("ida_gaia");
}

Maybe<string>
checkIDP(shared_ptr<istream> file_stream)
{
    string line;
    while (getline(*file_stream, line)) {
        if (line.find("<identity_portal/>") != string::npos) {
            return string("false");
        }
        if (line.find("<central_idp ") != string::npos) {
            return string("true");
        }
    }

    return genError("Identity Provider was not found");
}

#endif // gaia

#if defined(gaia) || defined(smb)

Maybe<string>
checkIsCpviewRunning(const string &command_output)
{
    if (command_output == "true" || command_output == "false") return command_output;

    return genError("cpview is not running");
}

Maybe<string>
checkIsCPotelcolGRET64(const string &command_output)
{
    if (command_output == "true" || command_output == "false") return command_output;

    return genError("CPotelcol is not installed or its take is below T64");
}

Maybe<string>
checkHasSDWan(const string &command_output)
{
    if (command_output.front() == '1') return string("true");

    return genError("Current host does not have SDWAN capability");
}

Maybe<string>
checkCanUpdateSDWanData(const string &command_output)
{
    if (command_output == "true" || command_output == "false") return command_output;

    return string("true");
}

Maybe<string>
getMgmtObjType(const string &command_output)
{
    if (!command_output.empty()) {
        if (command_output[0] == '1') return string("management");
        if (command_output[0] == '0') return string("gateway");
    }

    return genError("Object type was not found");
}

Maybe<string>
chopHeadAndTail(const string &str, const string &prefix, const string &suffix)
{
    if (str.size() < prefix.size() + suffix.size()) return genError("String too short");
    if (str.compare(0, prefix.size(), prefix)) return genError("Prefix mismatch");
    if (str.compare(str.size() - suffix.size(), suffix.size(), suffix)) return genError("Suffix mismatch");

    return str.substr(prefix.size(), str.size() - prefix.size() - suffix.size());
}

Maybe<string>
getMgmtObjAttr(shared_ptr<istream> file_stream, const string &attr)
{
    string line;
    while (getline(*file_stream, line)) {
        size_t attr_pos = line.find(attr);
        if (attr_pos == string::npos) continue;
        line = line.substr(attr_pos + attr.size());
        return chopHeadAndTail(line, "(", ")");
    }
    return genError("Object attribute was not found. Attr: " + attr);
}

Maybe<string>
getMgmtObjUid(shared_ptr<istream> file_stream)
{
    return getMgmtObjAttr(file_stream, "uuid ");
}

Maybe<string>
getMgmtObjName(shared_ptr<istream> file_stream)
{
    return getMgmtObjAttr(file_stream, "name ");
}

Maybe<string>
getGWHardware(const string &command_output)
{
    if (!command_output.empty()) {
        if (command_output == "software") return string("Open server");
        if (command_output == "Maestro Gateway") return string("Maestro");
        return string(command_output);
    }
    return genError("GW Hardware was not found");
}

Maybe<string>
getAttr(const string &command_output, const string &error)
{
    if (!command_output.empty()) {
        return string(command_output);
    }

    return genError(error);
}

Maybe<string>
getGWApplicationControlBlade(const string &command_output)
{
    return getAttr(command_output, "Application Control Blade was not found");
}

Maybe<string>
getGWURLFilteringBlade(const string &command_output)
{
    return getAttr(command_output, "URL Filtering Blade was not found");
}

Maybe<string>
getGWIPSecVPNBlade(const string &command_output)
{
    return getAttr(command_output, "IPSec VPN Blade was not found");
}

Maybe<string>
getGWIPAddress(const string &command_output)
{
    return getAttr(command_output, "IP Address was not found");
}

Maybe<string>
getGWVersion(const string &command_output)
{
    return getAttr(command_output, "GW Version was not found");
}

Maybe<string>
checkIfSdwanRunning(const string &command_output)
{
    if (command_output == "true" || command_output == "false") return command_output;

    return genError("Could not determine if sd-wan is running or not");
}

Maybe<string>
getClusterObjectIP(const string &command_output)
{
    return getAttr(command_output, "Cluster object IP was not found");
}

Maybe<string>
getSmbObjectName(const string &command_output)
{
    static const char centrally_managed_comd_output = '0';

    if (command_output.empty() || command_output[0] != centrally_managed_comd_output) {
        return genError("Object name was not found");
    }
    
    static const string obj_path = (getenv("FWDIR") ? string(getenv("FWDIR")) : "") + "/database/myown.C";
    auto ifs = std::make_shared<std::ifstream>(obj_path);
    if (!ifs->is_open()) {
        return genError("Failed to open the object file");
    }
    return getMgmtObjAttr(ifs, "name ");
}

Maybe<string>
getSmbBlade(const string &command_output, const string &error)
{
    if (command_output.front() == '1') return string("installed");
    if (command_output.front() == '0') return string("not-installed");

    return genError(error);
}

Maybe<string>
getSmbGWApplicationControlBlade(const string &command_output)
{
    return getSmbBlade(command_output, "Application Control Blade was not found");
}

Maybe<string>
getSmbGWURLFilteringBlade(const string &command_output)
{
    return getSmbBlade(command_output, "URL Filterin Blade was not found");
}

Maybe<string>
getSmbGWIPSecVPNBlade(const string &command_output)
{
    return getSmbBlade(command_output, "IPSec VPN Blade was not found");
}
#endif // gaia || smb

#if defined(gaia)
Maybe<string>
getMgmtParentObjUid(const string &command_output)
{
    return getAttr(command_output, "Parent object uuid was not found");
}

Maybe<string>
getMgmtParentObjName(const string &command_output)
{
    return getAttr(command_output, "Parent object name was not found");
}

#elif defined(smb)
Maybe<string>
getSmbMgmtParentObjUid(const string &command_output)
{
    if (!command_output.empty()) {
        return command_output;
    }
    return genError("Parent object uuid was not found.");
}

Maybe<string>
getSmbMgmtParentObjName(const string &command_output)
{
    if (!command_output.empty()) {
        return command_output;
    }
    return genError("Parent object name was not found.");
}
#endif // end if gaia/smb

Maybe<string>
getOsRelease(shared_ptr<istream> file_stream)
{
    string line;
    while (getline(*file_stream, line)) {
        if (line.find("Check Point") != string::npos) return line;

        static const string prety_name_attr = "PRETTY_NAME=";
        size_t pretty_name_idx = line.find(prety_name_attr);
        if (pretty_name_idx == string::npos) continue;
        line = line.substr(pretty_name_idx + prety_name_attr.size());
        if (line.front() == '"') line.erase(0, 1);
        if (line.back() == '"') line.pop_back();
        return line;
    }

    return genError("Os release was not found");
}

Maybe<string>
getWaapModelVersion(shared_ptr<istream> file_stream)
{
    string line;
    static const int max_lines = 5;
    int i = 0;
    bool found_key = false;
    while (i < max_lines && getline(*file_stream, line)) {
        if (!found_key) {
            size_t index = line.find("\"model_version\":");
            if (index != string::npos) {
                found_key = true;
            }
        } else {
            size_t start = line.find_first_of('"');
            size_t end = line.find_last_of('"');
            if (start != string::npos && end != string::npos && end > start) {
                return line.substr(start + 1, end - start - 1);
            } else {
                return genError("Model version value unreadable");
            }
        }
        i++;
    }

    return genError("Model version was not found");
}

#if defined(alpine)
string &
ltrim(string &s)
{
    auto it = find_if(
        s.begin(),
        s.end(),
        [](char c) { return !isspace<char>(c, locale::classic()); }
    );
    s.erase(s.begin(), it);
    return s;
}

string &
rtrim(string &s)
{
    auto it = find_if(
        s.rbegin(),
        s.rend(),
        [](char c) { return !isspace<char>(c, locale::classic()); }
    );
    s.erase(it.base(), s.end());
    return s;
}

string &
trim(string &s)
{
    return ltrim(rtrim(s));
}

Maybe<string>
getCPAlpineTag(shared_ptr<istream> file_stream)
{
    string line;
    while (getline(*file_stream, line)) {
        if (trim(line) != "") return line;
    }
    return genError("Alpine tag was not found");
}
#endif // alpine

#endif // __CHECKPOINT_PRODUCT_HANDLERS_H__
