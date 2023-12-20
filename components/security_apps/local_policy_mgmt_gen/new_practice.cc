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

#include "new_practice.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const set<string> performance_impacts    = {"low", "medium", "high"};
static const set<string> severity_levels        = {"low", "medium", "high", "critical"};
static const set<string> size_unit              = {"bytes", "KB", "MB", "GB"};
static const set<string> confidences_actions    = {"prevent", "detect", "inactive"};
static const set<string> valid_modes            = {"prevent", "detect", "inactive", "prevent-learn", "detect-learn"};
static const set<string> valid_confidences      = {"medium", "high", "critical"};
static const std::unordered_map<std::string, std::string> key_to_performance_impact_val = {
    { "low", "Low or lower"},
    { "medium", "Medium or lower"},
    { "high", "High or lower"}
};
static const std::unordered_map<std::string, std::string> key_to_severity_level_val = {
    { "low", "Low or above"},
    { "medium", "Medium or above"},
    { "high", "High or above"},
    { "critical", "Critical"}
};
static const std::unordered_map<std::string, std::string> key_to_mode_val = {
    { "prevent-learn", "Prevent"},
    { "detect-learn", "Detect"},
    { "prevent", "Prevent"},
    { "detect", "Detect"},
    { "inactive", "Inactive"}
};
static const std::unordered_map<std::string, uint64_t> unit_to_int = {
    { "bytes", 1},
    { "KB", 1024},
    { "MB", 1048576},
    { "GB", 1073741824}
};

void
NewAppSecWebBotsURI::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Bots URI";
    parseAppsecJSONKey<string>("uri", uri, archive_in);
}

const string &
NewAppSecWebBotsURI::getURI() const
{
    return uri;
}

std::vector<std::string>
NewAppSecPracticeAntiBot::getIjectedUris() const
{
    vector<string> injected;
    for (const NewAppSecWebBotsURI &uri : injected_uris) injected.push_back(uri.getURI());
    return injected;
}

std::vector<std::string>
NewAppSecPracticeAntiBot::getValidatedUris() const
{
    vector<string> validated;
    for (const NewAppSecWebBotsURI &uri : validated_uris) validated.push_back(uri.getURI());
    return validated;
}

void
NewAppSecPracticeAntiBot::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Bots";
    parseAppsecJSONKey<vector<NewAppSecWebBotsURI>>("injectedUris", injected_uris, archive_in);
    parseAppsecJSONKey<vector<NewAppSecWebBotsURI>>("validatedUris", validated_uris, archive_in);
    parseAppsecJSONKey<string>("overrideMode", override_mode, archive_in, "Inactive");
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Web Bots override mode invalid: " << override_mode;
    }
}

void
NewAppSecPracticeAntiBot::save(cereal::JSONOutputArchive &out_ar) const
{
    vector<string> injected;
    vector<string> validated;
    for (const NewAppSecWebBotsURI &uri : injected_uris) injected.push_back(uri.getURI());
    for (const NewAppSecWebBotsURI &uri : validated_uris) validated.push_back(uri.getURI());
    out_ar(
        cereal::make_nvp("injected", injected),
        cereal::make_nvp("validated", validated)
    );
}

void
NewAppSecWebAttackProtections::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Web Attack Protections";
    parseAppsecJSONKey<string>("csrfProtection", csrf_protection, archive_in, "inactive");
    parseAppsecJSONKey<string>("errorDisclosure", error_disclosure, archive_in, "inactive");
    parseAppsecJSONKey<string>("openRedirect", open_redirect, archive_in, "inactive");
    parseAppsecJSONKey<bool>("nonValidHttpMethods", non_valid_http_methods, archive_in, false);
}

const string
NewAppSecWebAttackProtections::getCsrfProtectionMode() const
{
    if (key_to_practices_val.find(csrf_protection) == key_to_practices_val.end()) {
        dbgError(D_LOCAL_POLICY)
            << "Failed to find a value for "
            << csrf_protection
            << ". Setting CSRF protection to Inactive";
        return "Inactive";
    }
    return key_to_practices_val.at(csrf_protection);
}

const string &
NewAppSecWebAttackProtections::getErrorDisclosureMode() const
{
    return error_disclosure;
}

bool
NewAppSecWebAttackProtections::getNonValidHttpMethods() const
{
    return non_valid_http_methods;
}

const string
NewAppSecWebAttackProtections::getOpenRedirectMode() const
{
    if (key_to_practices_val.find(open_redirect) == key_to_practices_val.end()) {
        dbgError(D_LOCAL_POLICY)
            << "Failed to find a value for "
            << open_redirect
            << ". Setting Open Redirect mode to Inactive";
        return "Inactive";
    }
    return key_to_practices_val.at(open_redirect);
}

void
NewAppSecPracticeWebAttacks::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec practice web attacks spec";
    parseAppsecJSONKey<NewAppSecWebAttackProtections>("protections", protections, archive_in);
    parseAppsecJSONKey<string>("overrideMode", mode, archive_in, "Unset");
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec practice override mode invalid: " << mode;
    }

    if (getMode() == "Prevent") {
        parseAppsecJSONKey<string>("minimumConfidence", minimum_confidence, archive_in, "critical");
        if (valid_confidences.count(minimum_confidence) == 0) {
            dbgWarning(D_LOCAL_POLICY)
                << "AppSec practice override minimum confidence invalid: "
                << minimum_confidence;
        }
    } else {
        minimum_confidence = "Transparent";
    }
    parseAppsecJSONKey<int>("maxBodySizeKb", max_body_size_kb, archive_in, 1000000);
    parseAppsecJSONKey<int>("maxHeaderSizeBytes", max_header_size_bytes, archive_in, 102400);
    parseAppsecJSONKey<int>("maxObjectDepth", max_object_depth, archive_in, 40);
    parseAppsecJSONKey<int>("maxUrlSizeBytes", max_url_size_bytes, archive_in, 32768);
}

int
NewAppSecPracticeWebAttacks::getMaxBodySizeKb() const
{
    return max_body_size_kb;
}

int
NewAppSecPracticeWebAttacks::getMaxHeaderSizeBytes() const
{
    return max_header_size_bytes;
}

int
NewAppSecPracticeWebAttacks::getMaxObjectDepth() const
{
    return max_object_depth;
}

int
NewAppSecPracticeWebAttacks::getMaxUrlSizeBytes() const
{
    return max_url_size_bytes;
}

const string &
NewAppSecPracticeWebAttacks::getMinimumConfidence() const
{
    return minimum_confidence;
}

const string &
NewAppSecPracticeWebAttacks::getMode(const string &default_mode) const
{
    if (mode == "Unset" || (key_to_practices_val2.find(mode) == key_to_practices_val2.end())) {
        dbgError(D_LOCAL_POLICY) << "Couldn't find a value for key: " << mode << ". Returning " << default_mode;
        return default_mode;
    }
    return key_to_practices_val2.at(mode);
}

SnortProtectionsSection::SnortProtectionsSection(
    const std::string               &_context,
    const std::string               &_asset_name,
    const std::string               &_asset_id,
    const std::string               &_practice_name,
    const std::string               &_practice_id,
    const std::string               &_source_identifier,
    const std::string               &_mode,
    const std::vector<std::string>  &_files)
        :
    context(_context),
    asset_name(_asset_name),
    asset_id(_asset_id),
    practice_name(_practice_name),
    practice_id(_practice_id),
    source_identifier(_source_identifier),
    mode(_mode),
    files(_files)
{
}

void
SnortProtectionsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",                         context),
        cereal::make_nvp("mode",                            key_to_mode_val.at(mode)),
        cereal::make_nvp("files",                           files),
        cereal::make_nvp("assetName",                       asset_name),
        cereal::make_nvp("assetId",                         asset_id),
        cereal::make_nvp("practiceName",                    practice_name),
        cereal::make_nvp("practiceId",                      practice_id),
        cereal::make_nvp("sourceIdentifier",                source_identifier)
    );
}

DetectionRules::DetectionRules(
    const std::string                   &_type,
    const std::string                   &_SSM,
    const std::string                   &_keywords,
    const std::vector<std::string>      &_context)
        :
    type(_type),
    SSM(_SSM),
    keywords(_keywords),
    context(_context)
{
}

void
DetectionRules::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Snort protections protections detection rules section";
    parseAppsecJSONKey<string>("type", type, archive_in);
    parseAppsecJSONKey<string>("SSM", SSM, archive_in);
    parseAppsecJSONKey<string>("keywords", keywords, archive_in);
    parseAppsecJSONKey<vector<string>>("context", context, archive_in);

}

void
DetectionRules::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("type",        type),
        cereal::make_nvp("SSM",         SSM),
        cereal::make_nvp("keywords",    keywords),
        cereal::make_nvp("context",     context)
    );
}

ProtectionMetadata::ProtectionMetadata(
    bool                                _silent,
    const std::string                   &_protection_name,
    const std::string                   &_severity,
    const std::string                   &_confidence_level,
    const std::string                   &_performance_impact,
    const std::string                   &_last_update,
    const std::string                   &_maintrain_id,
    const std::vector<std::string>      &_tags,
    const std::vector<std::string>      &_cve_list)
        :
    silent(_silent),
    protection_name(_protection_name),
    severity(_severity),
    confidence_level(_confidence_level),
    performance_impact(_performance_impact),
    last_update(_last_update),
    maintrain_id(_maintrain_id),
    tags(_tags),
    cve_list(_cve_list)
{
}

void
ProtectionMetadata::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Snort protections protections metadata section";
    parseAppsecJSONKey<bool>("silent", silent, archive_in);
    parseAppsecJSONKey<string>("protectionName", protection_name, archive_in);
    parseAppsecJSONKey<string>("severity", severity, archive_in);
    parseAppsecJSONKey<string>("confidenceLevel", confidence_level, archive_in);
    parseAppsecJSONKey<string>("performanceImpact", performance_impact, archive_in);
    parseAppsecJSONKey<string>("lastUpdate", last_update, archive_in);
    parseAppsecJSONKey<string>("maintrainId", maintrain_id, archive_in);
    parseAppsecJSONKey<vector<string>>("tags", tags, archive_in);
    parseAppsecJSONKey<vector<string>>("cveList", cve_list, archive_in);

}

void
ProtectionMetadata::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("protectionName",      protection_name),
        cereal::make_nvp("severity",            severity),
        cereal::make_nvp("confidenceLevel",     confidence_level),
        cereal::make_nvp("performanceImpact",   performance_impact),
        cereal::make_nvp("lastUpdate",          last_update),
        cereal::make_nvp("maintrainId",         maintrain_id),
        cereal::make_nvp("tags",                tags),
        cereal::make_nvp("cveList",             cve_list),
        cereal::make_nvp("silent",              silent)
    );
}

ProtectionsProtectionsSection::ProtectionsProtectionsSection(
    const ProtectionMetadata    &_protection_metadata,
    const DetectionRules        &_detection_rules)
        :
    protection_metadata(_protection_metadata),
    detection_rules(_detection_rules)
{
}

void
ProtectionsProtectionsSection::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Snort protections protections section";
    parseAppsecJSONKey<ProtectionMetadata>("protectionMetadata", protection_metadata, archive_in);
    parseAppsecJSONKey<DetectionRules>("detectionRules", detection_rules, archive_in);
}

void
ProtectionsProtectionsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("protectionMetadata",      protection_metadata),
        cereal::make_nvp("detectionRules",          detection_rules)
    );
}

ProtectionsSection::ProtectionsSection(
    const std::vector<ProtectionsProtectionsSection>    &_protections,
    const std::string                                   &_name,
    const std::string                                   &_modification_time)
        :
    protections(_protections),
    name(_name),
    modification_time(_modification_time)
{
}

void
ProtectionsSection::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Snort protections section";
    parseAppsecJSONKey<vector<ProtectionsProtectionsSection>>("protections", protections, archive_in);
}

void
ProtectionsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("name",                name),
        cereal::make_nvp("modificationTime",    modification_time),
        cereal::make_nvp("protections",         protections)
    );
}

const vector<ProtectionsProtectionsSection> &
ProtectionsSection::getProtections() const
{
    return protections;
}

void
ProtectionsSectionWrapper::serialize(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Snort Section";
    parseAppsecJSONKey<ProtectionsSection>("IPSSnortSigs", protections, archive_in);
}

const vector<ProtectionsProtectionsSection> &
ProtectionsSectionWrapper::getProtections() const
{
    return protections.getProtections();
}

void
SnortSection::save(cereal::JSONOutputArchive &out_ar) const
{
    string version = "LocalVersion";
    out_ar(
        cereal::make_nvp("VersionId", version),
        cereal::make_nvp("SnortProtections", snort_protections),
        cereal::make_nvp("protections", protections)
    );
}

void
SnortSectionWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("IPSSnortSigs", snort)
    );
}

void
NewSnortSignaturesAndOpenSchemaAPI::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Snort Signatures practice";
    parseAppsecJSONKey<string>("overrideMode", override_mode, archive_in, "inactive");
    parseAppsecJSONKey<vector<string>>("configmap", config_map, archive_in);
    parseAppsecJSONKey<vector<string>>("files", files, archive_in);
    is_temporary = false;
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Snort Signatures override mode invalid: " << override_mode;
    }
}

void
NewSnortSignaturesAndOpenSchemaAPI::addFile(const string &file_name)
{
    files.push_back(file_name);
}

const string &
NewSnortSignaturesAndOpenSchemaAPI::getOverrideMode() const
{
    return override_mode;
}

const vector<string> &
NewSnortSignaturesAndOpenSchemaAPI::getFiles() const
{
    return files;
}

const vector<string> &
NewSnortSignaturesAndOpenSchemaAPI::getConfigMap() const
{
    return config_map;
}

bool
NewSnortSignaturesAndOpenSchemaAPI::isTemporary() const
{
    return is_temporary;
}

void
NewSnortSignaturesAndOpenSchemaAPI::setTemporary(bool val)
{
    is_temporary = val;
}

void
IpsProtectionsRulesSection::save(cereal::JSONOutputArchive &out_ar) const
{
    vector<string> protections;
    out_ar(
        cereal::make_nvp("action",                  key_to_mode_val.at(action)),
        cereal::make_nvp("confidenceLevel",         confidence_level),
        cereal::make_nvp("clientProtections",       true),
        cereal::make_nvp("serverProtections",       true),
        cereal::make_nvp("protectionTags",          protections),
        cereal::make_nvp("protectionIds",           protections),
        cereal::make_nvp("performanceImpact",       key_to_performance_impact_val.at(performance_impact)),
        cereal::make_nvp("severityLevel",           key_to_severity_level_val.at(severity_level)),
        cereal::make_nvp("protectionsFromYear",     protections_from_year)
    );
}

IpsProtectionsSection::IpsProtectionsSection(
    const string &_context,
    const string &asset_name,
    const string &_asset_id,
    const string &_practice_name,
    const string &_practice_id,
    const string &_source_identifier,
    const string &_mode,
    const vector<IpsProtectionsRulesSection> &_rules)
        :
    context(_context),
    name(asset_name),
    asset_id(_asset_id),
    practice_name(_practice_name),
    practice_id(_practice_id),
    source_identifier(_source_identifier),
    mode(_mode),
    rules(_rules)
{
}

std::string &
IpsProtectionsSection::getMode()
{
    return mode;
}

void
IpsProtectionsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",             context),
        cereal::make_nvp("ruleName",            name),
        cereal::make_nvp("assetName",           name),
        cereal::make_nvp("assetId",             asset_id),
        cereal::make_nvp("practiceName",        practice_name),
        cereal::make_nvp("practiceId",          practice_id),
        cereal::make_nvp("sourceIdentifier",    source_identifier),
        cereal::make_nvp("defaultAction",       key_to_mode_val.at(mode)),
        cereal::make_nvp("rules",               rules)
    );
}

void
IPSSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("IpsProtections", ips)
    );
}

void
IntrusionPreventionWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("IPS", ips)
    );
}

void
NewIntrusionPrevention::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec Intrusion Prevention practice";
    parseAppsecJSONKey<string>("overrideMode", override_mode, archive_in, "inactive");
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec Intrusion Prevention override mode invalid: " << override_mode;
    }
    parseAppsecJSONKey<string>("maxPerformanceImpact", max_performance_impact, archive_in, "low");
    if (performance_impacts.count(max_performance_impact) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec Intrusion Prevention max performance impact invalid: "
            << max_performance_impact;
    }
    parseAppsecJSONKey<string>("minSeverityLevel", min_severity_level, archive_in, "low");
    if (severity_levels.count(min_severity_level) == 0) {
        dbgWarning(D_LOCAL_POLICY)
        << "AppSec Intrusion Prevention min severity level invalid: "
        << min_severity_level;
    }
    parseAppsecJSONKey<string>("highConfidenceEventAction", high_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(high_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
        << "AppSec Intrusion Prevention high confidence event invalid: "
        << high_confidence_event_action;
    }
    parseAppsecJSONKey<string>("mediumConfidenceEventAction", medium_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(medium_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
        << "AppSec Intrusion Prevention medium confidence event invalid: "
        << medium_confidence_event_action;
    }
    parseAppsecJSONKey<string>("lowConfidenceEventAction", low_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(low_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
        << "AppSec Intrusion Prevention low confidence event action invalid: "
        << low_confidence_event_action;
    }
    parseAppsecJSONKey<int>("minCveYear", min_cve_Year, archive_in);
}

vector<IpsProtectionsRulesSection>
NewIntrusionPrevention::createIpsRules() const
{
    vector<IpsProtectionsRulesSection> ips_rules;
    IpsProtectionsRulesSection high_rule(
        min_cve_Year,
        high_confidence_event_action,
        string("High"),
        max_performance_impact,
        string(""),
        min_severity_level
    );
    ips_rules.push_back(high_rule);

    IpsProtectionsRulesSection med_rule(
        min_cve_Year,
        medium_confidence_event_action,
        string("Medium"),
        max_performance_impact,
        string(""),
        min_severity_level
    );
    ips_rules.push_back(med_rule);

    IpsProtectionsRulesSection low_rule(
        min_cve_Year,
        low_confidence_event_action,
        string("Low"),
        max_performance_impact,
        string(""),
        min_severity_level
    );
    ips_rules.push_back(low_rule);

    return ips_rules;
}

const std::string &
NewIntrusionPrevention::getMode() const
{
    return override_mode;
}

FileSecurityProtectionsSection::FileSecurityProtectionsSection(
    uint64_t                _file_size_limit,
    uint64_t                _archive_file_size_limit,
    bool                    _allow_files_without_name,
    bool                    _required_file_size_limit,
    bool                    _required_archive_extraction,
    const std::string       &_context,
    const std::string       &_name,
    const std::string       &_asset_id,
    const std::string       &_practice_name,
    const std::string       &_practice_id,
    const std::string       &_action,
    const std::string       &_files_without_name_action,
    const std::string       &_high_confidence_action,
    const std::string       &_medium_confidence_action,
    const std::string       &_low_confidence_action,
    const std::string       &_severity_level,
    const std::string       &_file_size_limit_action,
    const std::string       &_multi_level_archive_action,
    const std::string       &_unopened_archive_action)
        :
    file_size_limit(_file_size_limit),
    archive_file_size_limit(_archive_file_size_limit),
    allow_files_without_name(_allow_files_without_name),
    required_file_size_limit(_required_file_size_limit),
    required_archive_extraction(_required_archive_extraction),
    context(_context),
    name(_name),
    asset_id(_asset_id),
    practice_name(_practice_name),
    practice_id(_practice_id),
    action(_action),
    files_without_name_action(_files_without_name_action),
    high_confidence_action(_high_confidence_action),
    medium_confidence_action(_medium_confidence_action),
    low_confidence_action(_low_confidence_action),
    severity_level(_severity_level),
    file_size_limit_action(_file_size_limit_action),
    multi_level_archive_action(_multi_level_archive_action),
    unopened_archive_action(_unopened_archive_action)
{}

void
FileSecurityProtectionsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("context",                         context),
        cereal::make_nvp("ruleName",                        name),
        cereal::make_nvp("assetName",                       name),
        cereal::make_nvp("assetId",                         asset_id),
        cereal::make_nvp("practiceName",                    practice_name),
        cereal::make_nvp("practiceId",                      practice_id),
        cereal::make_nvp("action",                          key_to_mode_val.at(action)),
        cereal::make_nvp("filesWithoutNameAction",          key_to_mode_val.at(files_without_name_action)),
        cereal::make_nvp("allowFilesWithoutName",           allow_files_without_name),
        cereal::make_nvp("highConfidence",                  key_to_mode_val.at(high_confidence_action)),
        cereal::make_nvp("mediumConfidence",                key_to_mode_val.at(medium_confidence_action)),
        cereal::make_nvp("lowConfidence",                   key_to_mode_val.at(low_confidence_action)),
        cereal::make_nvp("severityLevel",                   key_to_severity_level_val.at(severity_level)),
        cereal::make_nvp("fileSizeLimitAction",             key_to_mode_val.at(file_size_limit_action)),
        cereal::make_nvp("fileSizeLimit",                   file_size_limit),
        cereal::make_nvp("requiredFileSizeLimit",           required_file_size_limit),
        cereal::make_nvp("requiredArchiveExtraction",       required_archive_extraction),
        cereal::make_nvp("archiveFileSizeLimit",            archive_file_size_limit),
        cereal::make_nvp("MultiLevelArchiveAction",         key_to_mode_val.at(multi_level_archive_action)),
        cereal::make_nvp("UnopenedArchiveAction",           key_to_mode_val.at(unopened_archive_action))
    );
}

void
FileSecuritySection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("FileSecurityProtections", file_security)
    );
}

void
FileSecurityWrapper::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("FileSecurity", file_security)
    );
}

void
NewFileSecurityArchiveInspection::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec File Security Archive Inspection practice";
    parseAppsecJSONKey<bool>("extractArchiveFiles", extract_archive_files, archive_in);
    parseAppsecJSONKey<uint64_t>("scanMaxFileSize", scan_max_file_size, archive_in, 0);
    parseAppsecJSONKey<string>("scanMaxFileSizeUnit", scan_max_file_size_unit, archive_in, "bytes");
    if (size_unit.count(scan_max_file_size_unit) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security Archive Inspection scan max file size unit invalid: "
            << scan_max_file_size_unit;
    }
    parseAppsecJSONKey<string>(
        "archivedFilesWithinArchivedFiles",
        archived_files_within_archived_files,
        archive_in,
        "inactive");
    if (confidences_actions.count(archived_files_within_archived_files) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security Archive Inspection archived files within archived files invalid: "
            << archived_files_within_archived_files;
    }
    parseAppsecJSONKey<string>(
        "archivedFilesWhereContentExtractionFailed",
        archived_files_where_content_extraction_failed,
        archive_in,
        "inactive");
    if (confidences_actions.count(archived_files_where_content_extraction_failed) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security Archive Inspection archived files within archived file invalid: "
            << archived_files_where_content_extraction_failed;
    }
}

uint64_t
NewFileSecurityArchiveInspection::getArchiveFileSizeLimit() const
{
    if (unit_to_int.find(scan_max_file_size_unit) == unit_to_int.end()) {
        dbgError(D_LOCAL_POLICY)
            << "Failed to find a value for "
            << scan_max_file_size_unit
            << ". Setting scan max file size unit to 0";
        return 0;
    }
    return (scan_max_file_size * unit_to_int.at(scan_max_file_size_unit));
}

bool
NewFileSecurityArchiveInspection::getrequiredArchiveExtraction() const
{
    return extract_archive_files;
}

const std::string &
NewFileSecurityArchiveInspection::getMultiLevelArchiveAction() const
{
    return archived_files_within_archived_files;
}

const std::string &
NewFileSecurityArchiveInspection::getUnopenedArchiveAction() const
{
    return archived_files_where_content_extraction_failed;
}

void
NewFileSecurityLargeFileInspection::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec File Security large File Inspection practice";
    parseAppsecJSONKey<uint64_t>("fileSizeLimit", file_size_limit, archive_in);
    parseAppsecJSONKey<string>("fileSizeLimitUnit", file_size_limit_unit, archive_in, "bytes");
    if (size_unit.count(file_size_limit_unit) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security large File Inspection file size limit unit invalid: "
            << file_size_limit_unit;
    }
    parseAppsecJSONKey<string>(
        "filesExceedingSizeLimitAction",
        files_exceeding_size_limit_action,
        archive_in,
        "inactive");
    if (confidences_actions.count(files_exceeding_size_limit_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security Archive Inspection archived files within archived files invalid: "
            << files_exceeding_size_limit_action;
    }
}

uint64_t
NewFileSecurityLargeFileInspection::getFileSizeLimit() const
{
    if (unit_to_int.find(file_size_limit_unit) == unit_to_int.end()) {
        dbgError(D_LOCAL_POLICY)
            << "Failed to find a value for "
            << file_size_limit_unit
            << ". Setting file size limit unit to 0";
        return 0;
    }
    return (file_size_limit * unit_to_int.at(file_size_limit_unit));
}

const std::string &
NewFileSecurityLargeFileInspection::getFileSizeLimitAction() const
{
    return files_exceeding_size_limit_action;
}

void
NewFileSecurity::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec File Security practice";
    parseAppsecJSONKey<string>("overrideMode", override_mode, archive_in, "inactive");
    if (valid_modes.count(override_mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec File Security override mode invalid: " << override_mode;
    }
    parseAppsecJSONKey<string>("minSeverityLevel", min_severity_level, archive_in, "low");
    if (severity_levels.count(min_severity_level) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec File Security min severity level invalid: " << min_severity_level;
    }
    parseAppsecJSONKey<string>("highConfidenceEventAction", high_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(high_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security high confidence event invalid: "
            << high_confidence_event_action;
    }
    parseAppsecJSONKey<string>("mediumConfidenceEventAction", medium_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(medium_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security medium confidence event invalid: "
            << medium_confidence_event_action;
    }
    parseAppsecJSONKey<string>("lowConfidenceEventAction", low_confidence_event_action, archive_in, "inactive");
    if (confidences_actions.count(low_confidence_event_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security low confidence event action invalid: "
            << low_confidence_event_action;
    }
    parseAppsecJSONKey<string>("unnamedFilesAction", unnamed_files_action, archive_in, "inactive");
    if (confidences_actions.count(unnamed_files_action) == 0) {
        dbgWarning(D_LOCAL_POLICY)
            << "AppSec File Security low unnamed files action invalid: "
            << unnamed_files_action;
    }
    parseAppsecJSONKey<bool>("threatEmulationEnabled", threat_emulation_enabled, archive_in);
    parseAppsecJSONKey<NewFileSecurityArchiveInspection>("archiveInspection", archive_inspection, archive_in);
    parseAppsecJSONKey<NewFileSecurityLargeFileInspection>("largeFileInspection", large_file_inspection, archive_in);
}

const string &
NewFileSecurity::getOverrideMode() const
{
    return override_mode;
}

const NewFileSecurityArchiveInspection &
NewFileSecurity::getArchiveInspection() const
{
    return archive_inspection;
}

const NewFileSecurityLargeFileInspection &
NewFileSecurity::getLargeFileInspection() const
{
    return large_file_inspection;
}

FileSecurityProtectionsSection
NewFileSecurity::createFileSecurityProtectionsSection(
    const string &context,
    const string &asset_name,
    const string &asset_id,
    const string &practice_name,
    const string &practice_id) const
{
    return FileSecurityProtectionsSection(
        getLargeFileInspection().getFileSizeLimit(),
        getArchiveInspection().getArchiveFileSizeLimit(),
        unnamed_files_action == "prevent" ? true : false,
        getLargeFileInspection().getFileSizeLimitAction() == "prevent" ? true : false,
        getArchiveInspection().getrequiredArchiveExtraction(),
        context,
        asset_name,
        asset_id,
        practice_name,
        practice_id,
        override_mode,
        unnamed_files_action,
        high_confidence_event_action,
        medium_confidence_event_action,
        low_confidence_event_action,
        min_severity_level,
        getLargeFileInspection().getFileSizeLimitAction(),
        getArchiveInspection().getMultiLevelArchiveAction(),
        getArchiveInspection().getUnopenedArchiveAction()
    );
}

void
NewAppSecPracticeSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading AppSec practice spec";
    parseAppsecJSONKey<NewSnortSignaturesAndOpenSchemaAPI>(
        "openapi-schema-validation",
        openapi_schema_validation,
        archive_in
    );
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<NewFileSecurity>("fileSecurity", file_security, archive_in);
    parseAppsecJSONKey<NewIntrusionPrevention>("intrusionPrevention", intrusion_prevention, archive_in);
    parseAppsecJSONKey<NewSnortSignaturesAndOpenSchemaAPI>("snortSignatures", snort_signatures, archive_in);
    parseAppsecJSONKey<NewAppSecPracticeWebAttacks>("webAttacks", web_attacks, archive_in);
    parseAppsecJSONKey<NewAppSecPracticeAntiBot>("antiBot", anti_bot, archive_in);
    parseAppsecJSONKey<string>("name", practice_name, archive_in);
}

void
NewAppSecPracticeSpec::setName(const string &_name)
{
    practice_name = _name;
}

const NewSnortSignaturesAndOpenSchemaAPI &
NewAppSecPracticeSpec::getOpenSchemaValidation() const
{
    return openapi_schema_validation;
}

NewSnortSignaturesAndOpenSchemaAPI &
NewAppSecPracticeSpec::getSnortSignatures()
{
    return snort_signatures;
}

const NewAppSecPracticeWebAttacks &
NewAppSecPracticeSpec::getWebAttacks() const
{
    return web_attacks;
}

const NewAppSecPracticeAntiBot &
NewAppSecPracticeSpec::getAntiBot() const
{
    return anti_bot;
}

const NewIntrusionPrevention &
NewAppSecPracticeSpec::getIntrusionPrevention() const
{
    return intrusion_prevention;
}

const NewFileSecurity &
NewAppSecPracticeSpec::getFileSecurity() const
{
    return file_security;
}

const string &
NewAppSecPracticeSpec::getAppSecClassName() const
{
    return appsec_class_name;
}

const string &
NewAppSecPracticeSpec::getName() const
{
    return practice_name;
}
// LCOV_EXCL_STOP
