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

#ifndef __NEW_PRACTICE_H__
#define __NEW_PRACTICE_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"

class IpsProtectionsRulesSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    IpsProtectionsRulesSection() {};

    IpsProtectionsRulesSection(
    const int _protections_from_year,
    const std::string &_action,
    const std::string &_confidence_level,
    const std::string &_performance_impact,
    const std::string &_source_identifier,
    const std::string &_severity_level
    )
        :
    protections_from_year(_protections_from_year),
    action(_action),
    confidence_level(_confidence_level),
    performance_impact(_performance_impact),
    source_identifier(_source_identifier),
    severity_level(_severity_level)
    {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    int                         protections_from_year;
    std::string                 action;
    std::string                 confidence_level;
    std::string                 performance_impact;
    std::string                 source_identifier;
    std::string                 severity_level;
};

class IpsProtectionsSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    IpsProtectionsSection() {};
    // LCOV_EXCL_STOP

    IpsProtectionsSection(
    const std::string &_context,
    const std::string &asset_name,
    const std::string &_asset_id,
    const std::string &_practice_name,
    const std::string &_practice_id,
    const std::string &_source_identifier,
    const std::string &_mode,
    const std::vector<IpsProtectionsRulesSection> &_rules);

    std::string & getMode();

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string                                 context;
    std::string                                 name;
    std::string                                 asset_id;
    std::string                                 practice_name;
    std::string                                 practice_id;
    std::string                                 source_identifier;
    std::string                                 mode;
    std::vector<IpsProtectionsRulesSection>     rules;
};

class IPSSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    IPSSection() {};

    IPSSection(const std::vector<IpsProtectionsSection> &_ips) : ips(_ips) {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<IpsProtectionsSection> ips;
};

class IntrusionPreventionWrapper
{
public:
    // LCOV_EXCL_START Reason: no test exist
    IntrusionPreventionWrapper() {};

    IntrusionPreventionWrapper(const std::vector<IpsProtectionsSection> &_ips) : ips(IPSSection(_ips)) {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    IPSSection ips;
};

class NewIntrusionPrevention
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    std::vector<IpsProtectionsRulesSection> createIpsRules() const;
    const std::string & getMode() const;

private:
    std::string override_mode;
    std::string max_performance_impact;
    std::string min_severity_level;
    std::string high_confidence_event_action;
    std::string medium_confidence_event_action;
    std::string low_confidence_event_action;
    int         min_cve_Year;
};

class FileSecurityProtectionsSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    FileSecurityProtectionsSection() {};
    // LCOV_EXCL_STOP

    FileSecurityProtectionsSection(
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
        const std::string       &_unopened_archive_action
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    uint64_t                                    file_size_limit;
    uint64_t                                    archive_file_size_limit;
    bool                                        allow_files_without_name;
    bool                                        required_file_size_limit;
    bool                                        required_archive_extraction;
    std::string                                 context;
    std::string                                 name;
    std::string                                 asset_id;
    std::string                                 practice_name;
    std::string                                 practice_id;
    std::string                                 action;
    std::string                                 files_without_name_action;
    std::string                                 high_confidence_action;
    std::string                                 medium_confidence_action;
    std::string                                 low_confidence_action;
    std::string                                 severity_level;
    std::string                                 file_size_limit_action;
    std::string                                 file_size_limit_unit;
    std::string                                 scan_max_file_size_unit;
    std::string                                 multi_level_archive_action;
    std::string                                 unopened_archive_action;
};

class FileSecuritySection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    FileSecuritySection() {};

    FileSecuritySection(const std::vector<FileSecurityProtectionsSection> &_file_security)
        :
    file_security(_file_security) {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::vector<FileSecurityProtectionsSection> file_security;
};

class FileSecurityWrapper
{
public:
    // LCOV_EXCL_START Reason: no test exist
    FileSecurityWrapper() {};

    FileSecurityWrapper(const std::vector<FileSecurityProtectionsSection> &_file_security)
        :
    file_security(FileSecuritySection(_file_security)) {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    FileSecuritySection file_security;
};

class NewFileSecurityArchiveInspection
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    uint64_t getArchiveFileSizeLimit() const;
    bool getrequiredArchiveExtraction() const;
    const std::string & getMultiLevelArchiveAction() const;
    const std::string & getUnopenedArchiveAction() const;

private:
    uint64_t    scan_max_file_size;
    bool        extract_archive_files;
    std::string scan_max_file_size_unit;
    std::string archived_files_within_archived_files;
    std::string archived_files_where_content_extraction_failed;
};

class NewFileSecurityLargeFileInspection
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    uint64_t getFileSizeLimit() const;
    const std::string & getFileSizeLimitAction() const;

private:
    uint64_t    file_size_limit;
    std::string file_size_limit_unit;
    std::string files_exceeding_size_limit_action;
};

class NewFileSecurity
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getOverrideMode() const;
    const NewFileSecurityArchiveInspection & getArchiveInspection() const;
    const NewFileSecurityLargeFileInspection & getLargeFileInspection() const;
    FileSecurityProtectionsSection createFileSecurityProtectionsSection(
        const std::string &context,
        const std::string &asset_name,
        const std::string &asset_id,
        const std::string &practice_name,
        const std::string &practice_id
    ) const;

private:
    bool                                threat_emulation_enabled;
    std::string                         override_mode;
    std::string                         min_severity_level;
    std::string                         high_confidence_event_action;
    std::string                         medium_confidence_event_action;
    std::string                         low_confidence_event_action;
    std::string                         unnamed_files_action;
    NewFileSecurityArchiveInspection    archive_inspection;
    NewFileSecurityLargeFileInspection  large_file_inspection;
};

class SnortProtectionsSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    SnortProtectionsSection() {};
    // LCOV_EXCL_STOP

    SnortProtectionsSection(
        const std::string               &_context,
        const std::string               &_asset_name,
        const std::string               &_asset_id,
        const std::string               &_practice_name,
        const std::string               &_practice_id,
        const std::string               &_source_identifier,
        const std::string               &_mode,
        const std::vector<std::string>  &_files
    );

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string                                 context;
    std::string                                 asset_name;
    std::string                                 asset_id;
    std::string                                 practice_name;
    std::string                                 practice_id;
    std::string                                 source_identifier;
    std::string                                 mode;
    std::vector<std::string>                    files;
};

class DetectionRules
{
public:
    // LCOV_EXCL_START Reason: no test exist
    DetectionRules() {};
    // LCOV_EXCL_STOP

    DetectionRules(
        const std::string                   &_type,
        const std::string                   &_SSM,
        const std::string                   &_keywords,
        const std::vector<std::string>      &_context
    );

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string                 type;
    std::string                 SSM;
    std::string                 keywords;
    std::vector<std::string>    context;
};

class ProtectionMetadata
{
public:
    // LCOV_EXCL_START Reason: no test exist
    ProtectionMetadata() {};
    // LCOV_EXCL_STOP

    ProtectionMetadata(
        bool                                _silent,
        const std::string                   &_protection_name,
        const std::string                   &_severity,
        const std::string                   &_confidence_level,
        const std::string                   &_performance_impact,
        const std::string                   &_last_update,
        const std::string                   &_maintrain_id,
        const std::vector<std::string>      &_tags,
        const std::vector<std::string>      &_cve_list
    );

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    bool                        silent;
    std::string                 protection_name;
    std::string                 severity;
    std::string                 confidence_level;
    std::string                 performance_impact;
    std::string                 last_update;
    std::string                 maintrain_id;
    std::vector<std::string>    tags;
    std::vector<std::string>    cve_list;
};

class ProtectionsProtectionsSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    ProtectionsProtectionsSection() {};
    // LCOV_EXCL_STOP

    ProtectionsProtectionsSection(
        const ProtectionMetadata    &_protection_metadata,
        const DetectionRules        &_detection_rules
    );

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    ProtectionMetadata  protection_metadata;
    DetectionRules      detection_rules;
};

class ProtectionsSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    ProtectionsSection() {};
    // LCOV_EXCL_STOP

    ProtectionsSection(
        const std::vector<ProtectionsProtectionsSection>    &_protections,
        const std::string                                   &_name = "",
        const std::string                                   &_modification_time = ""
    );

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::vector<ProtectionsProtectionsSection> & getProtections() const;

private:
    std::vector<ProtectionsProtectionsSection>  protections;
    std::string                                 name;
    std::string                                 modification_time;
};

class ProtectionsSectionWrapper
{
public:
    // LCOV_EXCL_START Reason: no test exist
    ProtectionsSectionWrapper() {};
    // LCOV_EXCL_STOP

    void serialize(cereal::JSONInputArchive &archive_in);
    const std::vector<ProtectionsProtectionsSection> & getProtections() const;

private:
    ProtectionsSection  protections;
};

class SnortSection
{
public:
    // LCOV_EXCL_START Reason: no test exist
    SnortSection() {};

    SnortSection(
        const std::vector<SnortProtectionsSection> &_snort,
        const std::vector<ProtectionsSection> &_protections)
            :
        snort_protections(_snort),
        protections(_protections)
    {};
    // LCOV_EXCL_STOP

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::vector<ProtectionsSection> & getProtections() const;

private:
    std::vector<SnortProtectionsSection> snort_protections;
    std::vector<ProtectionsSection> protections;
};

class SnortSectionWrapper
{
public:
    // LCOV_EXCL_START Reason: no test exist
    SnortSectionWrapper() {};

    SnortSectionWrapper(
        const std::vector<SnortProtectionsSection> &_snort,
        const std::vector<ProtectionsSection> &_protections)
            :
        snort(SnortSection(_snort, _protections))
    {};
    // LCOV_EXCL_STOP

    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    SnortSection snort;
};

class NewSnortSignaturesAndOpenSchemaAPI
{
public:
    NewSnortSignaturesAndOpenSchemaAPI() : is_temporary(false) {};

    void load(cereal::JSONInputArchive &archive_in);

    void addFile(const std::string &file_name);
    const std::string & getOverrideMode() const;
    const std::vector<std::string> & getConfigMap() const;
    const std::vector<std::string> & getFiles() const;
    bool isTemporary() const;
    void setTemporary(bool val);

private:
    std::string override_mode;
    std::vector<std::string> config_map;
    std::vector<std::string> files;
    bool is_temporary;
};

class NewAppSecWebBotsURI
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getURI() const;

private:
    std::string uri;
};

class NewAppSecPracticeAntiBot
{
public:
    std::vector<std::string> getIjectedUris() const;
    std::vector<std::string> getValidatedUris() const;

    void load(cereal::JSONInputArchive &archive_in);
    void save(cereal::JSONOutputArchive &out_ar) const;

private:
    std::string override_mode;
    std::vector<NewAppSecWebBotsURI> injected_uris;
    std::vector<NewAppSecWebBotsURI> validated_uris;
};

class NewAppSecWebAttackProtections
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string getCsrfProtectionMode() const;
    const std::string & getErrorDisclosureMode() const;
    bool getNonValidHttpMethods() const;
    const std::string getOpenRedirectMode() const;

private:
    std::string csrf_protection;
    std::string open_redirect;
    std::string error_disclosure;
    bool non_valid_http_methods;
};

class NewAppSecPracticeWebAttacks
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getMaxBodySizeKb() const;
    int getMaxHeaderSizeBytes() const;
    int getMaxObjectDepth() const;
    int getMaxUrlSizeBytes() const;
    const std::string & getMinimumConfidence() const;
    const NewAppSecWebAttackProtections & getprotections() const;
    const std::string & getMode(const std::string &default_mode = "Inactive") const;

private:
    int                             max_body_size_kb;
    int                             max_header_size_bytes;
    int                             max_object_depth;
    int                             max_url_size_bytes;
    std::string                     mode;
    std::string                     minimum_confidence;
    NewAppSecWebAttackProtections   protections;
};

class NewAppSecPracticeSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    NewSnortSignaturesAndOpenSchemaAPI & getSnortSignatures();
    const NewSnortSignaturesAndOpenSchemaAPI & getOpenSchemaValidation() const;
    const NewAppSecPracticeWebAttacks & getWebAttacks() const;
    const NewAppSecPracticeAntiBot & getAntiBot() const;
    const NewIntrusionPrevention & getIntrusionPrevention() const;
    const NewFileSecurity & getFileSecurity() const;
    const std::string & getAppSecClassName() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    NewFileSecurity                             file_security;
    NewIntrusionPrevention                      intrusion_prevention;
    NewSnortSignaturesAndOpenSchemaAPI          openapi_schema_validation;
    NewSnortSignaturesAndOpenSchemaAPI          snort_signatures;
    NewAppSecPracticeWebAttacks                 web_attacks;
    NewAppSecPracticeAntiBot                    anti_bot;
    std::string                                 appsec_class_name;
    std::string                                 practice_name;
};

#endif // __NEW_PRACTICE_H__
