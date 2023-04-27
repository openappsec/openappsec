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

#include "report/report.h"

#include <sstream>
#include <algorithm>

#include "i_encryptor.h"

using namespace std;

USE_DEBUG_FLAG(D_INFRA);

class SyslogReport
{
public:
    SyslogReport() = default;

    void
    push(const string &in)
    {
        if (!is_init) {
            is_init = true;
        } else {
            data << " ";
        }

        data << in;
    }

    string
    toString()
    {
        return data.str();
    }

private:
    bool is_init = false;
    stringstream data;
};

class CefReport
{
public:
    CefReport() = default;

    void
    pushMandatory(const string &in)
    {
        data << in << "|";
        mandetory_fields_count++;
    }

    void
    pushExtension(const string &in)
    {
        static uint mandetory_fields_before_extension = 7;
        if (mandetory_fields_count < mandetory_fields_before_extension) {
            dbgWarning(D_INFRA)
                << "Cennot build CEF log, There must be "
                << mandetory_fields_before_extension
                <<  " before adding extension fields";
            return;
        }
        if (!is_init) {
            is_init = true;
        } else {
            data << " ";
        }

        data << in;
    }

    string
    toString()
    {
        return data.str();
    }

private:
    bool is_init = false;
    uint mandetory_fields_count = 0;
    stringstream data;
};

const string LogField::Details::cp_xor = "ChkPoint";
const string LogField::Details::cp_xor_label = "{XORANDB64}:";

string
LogField::Details::obfuscateChkPoint(const string &orig)
{
    string res;
    res.reserve(orig.size());

    for (size_t i = 0; i < orig.size(); i++) {
        auto j = i % cp_xor.size();
        res += orig[i] ^ cp_xor[j];
    }

    return cp_xor_label + Singleton::Consume<I_Encryptor>::by<Debug>()->base64Encode(res);
}

void
Report::serialize(cereal::JSONOutputArchive &ar) const
{
    auto i_time = Singleton::Consume<I_TimeGet>::by<Report>();
    string time_stamp = i_time->getWalltimeStr(time);
    if (time_stamp.size() > 7 && time_stamp[time_stamp.size() - 7] == '.') {
        time_stamp.erase(time_stamp.size() - 3); // downscale micro-sec resollution to milli-sec
    }
    ar( cereal::make_nvp("eventTime",         time_stamp),
        cereal::make_nvp("eventName",         title),
        cereal::make_nvp("eventSeverity",     TagAndEnumManagement::convertToString(severity)),
        cereal::make_nvp("eventPriority",     TagAndEnumManagement::convertToString(priority)),
        cereal::make_nvp("eventType",         TagAndEnumManagement::convertToString(type)),
        cereal::make_nvp("eventLevel",        TagAndEnumManagement::convertToString(level)),
        cereal::make_nvp("eventLogLevel",     TagAndEnumManagement::convertToString(log_level)),
        cereal::make_nvp("eventAudience",     TagAndEnumManagement::convertToString(audience)),
        cereal::make_nvp("eventAudienceTeam", TagAndEnumManagement::convertToString(audience_team)),
        cereal::make_nvp("eventFrequency",    frequency),
        cereal::make_nvp("eventTags",         TagAndEnumManagement::convertToString(tags))
    );

    origin.serialize(ar);
    event_data.serialize(ar);
}

string
Report::getSyslog() const
{
    static int counter = 0;
    SyslogReport report;

    auto i_time = Singleton::Consume<I_TimeGet>::by<Report>();
    string time_stamp = i_time->getWalltimeStr(time);
    if (time_stamp.size() > 7 && time_stamp[time_stamp.size() - 7] == '.') {
        time_stamp.erase(time_stamp.size() - 3); // downscale micro-sec resoloution to milli-sec
    }
    time_stamp += "Z";

    string origin_syslog = origin.getSyslogAndCef();
    string event_data_syslog = event_data.getSyslogAndCef();
    string agent_id = "cpnano-agent-" + Singleton::Consume<I_AgentDetails>::by<Report>()->getAgentId();
    auto service_name = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Name");

    if (service_name.ok()) {
        string tmp = service_name.unpack();
        tmp.erase(remove_if(tmp.begin(), tmp.end(), [](const char &t) { return t == ' '; }), tmp.end());
        service_name = tmp;
    } else {
        service_name = "UnnamedNanoService";
    }

    // Facility (Value 16), Severity (Value 5) and Version (Value 1) 16*8+5= 133
    report.push("<133>1");
    report.push(time_stamp); // Timestamp
    report.push(agent_id); // Hostname
    report.push(*service_name); // App-name
    report.push("-"); // Process-Id (Null)
    report.push(to_string(counter++)); // Message-ID
    report.push("-"); // Strcutred-data (Null)

    // Message payload
    report.push("title='" + title + "'");
    if (!origin_syslog.empty()) {
        report.push(origin_syslog);
    }
    if (!event_data_syslog.empty()) {
        report.push(event_data_syslog);
    }

    return report.toString();
}

string
Report::getCef() const
{
    CefReport report;
    auto service_name = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Name");

    auto i_time = Singleton::Consume<I_TimeGet>::by<Report>();
    string time_stamp = i_time->getWalltimeStr(time);
    if (time_stamp.size() > 7 && time_stamp[time_stamp.size() - 7] == '.') {
        time_stamp.erase(time_stamp.size() - 3); // downscale micro-sec resollution to milli-sec
    }

    if (service_name.ok()) {
        string tmp = service_name.unpack();
        tmp.erase(remove(tmp.begin(), tmp.end(), ' '), tmp.end());
        service_name = tmp;
    } else {
        service_name = "UnnamedNanoService";
    }
    string version = "";
    report.pushMandatory("CEF:0");
    report.pushMandatory("Check Point");
    report.pushMandatory(*service_name);
    report.pushMandatory(version);
    report.pushMandatory(TagAndEnumManagement::convertToString(type));
    report.pushMandatory(title);
    report.pushMandatory(TagAndEnumManagement::convertToString(priority));

    string origin_cef = origin.getSyslogAndCef();
    string event_data_cef = event_data.getSyslogAndCef();

    report.pushExtension("eventTime=" + time_stamp);
    if (!origin_cef.empty()) {
        report.pushExtension(origin_cef);
    }
    if (!event_data_cef.empty()) {
        report.pushExtension(event_data_cef);
    }

    return report.toString();
}

Report &
Report::operator<<(const LogField &log)
{
    event_data.addFields(log);
    return *this;
}

void
Report::addToOrigin(const LogField &field)
{
    origin.addFields(field);
}

void
Report::setTenantID()
{
    if (Singleton::exists<I_Environment>()) {
        auto tenant_id = Singleton::Consume<I_Environment>::by<Report>()->get<string>("ActiveTenantId");
        if (tenant_id.ok()) origin.addFields(LogField("eventTenantId", *tenant_id));
    }
}

void
Report::setTraceID()
{
    string trace_id;
    if (Singleton::exists<I_Environment>()) {
        trace_id = Singleton::Consume<I_Environment>::by<Report>()->getCurrentTrace();
    }
    origin.addFields(LogField("eventTraceId", trace_id));
}

void
Report::setSpanID()
{
    string span_id;
    if (Singleton::exists<I_Environment>()) {
        span_id =  Singleton::Consume<I_Environment>::by<Report>()->getCurrentSpan();
    }
    origin.addFields(LogField("eventSpanId", span_id));
}

void
Report::setEngineVersion()
{
    string engine_version;
    if (Singleton::exists<I_Environment>()) {
        auto version = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Version");
        if (version.ok()) engine_version = *version;
    }

    origin.addFields(LogField("issuingEngineVersion", engine_version));
}

void
Report::setServiceName()
{
    string service_name = "Unnamed Nano Service";
    if (Singleton::exists<I_Environment>()) {
        auto name = Singleton::Consume<I_Environment>::by<Report>()->get<string>("Service Name");
        if (name.ok()) service_name = *name;
    }
    origin.addFields(LogField("serviceName", service_name));
}

void
Report::setInstanceAwareness()
{
    if (Singleton::exists<I_InstanceAwareness>()) {
        auto instance_awareness = Singleton::Consume<I_InstanceAwareness>::by<Report>();
        auto uid = instance_awareness->getUniqueID();
        auto family_id = instance_awareness->getFamilyID();
        if (uid.ok()) origin.addFields(LogField("serviceId", uid.unpack()));
        if (family_id.ok()) origin.addFields(LogField("serviceFamilyId", family_id.unpack()));
    }
}
