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

/// \file ips_signatures.h
/// \brief Declaration of classes IPSSignatureSubTypes, IPSSignaturesPerContext, IPSSignatures, SnortSignatures, and
/// related functions. \author Check Point Software Technologies Ltd. \date 2022

#ifndef __IPS_SIGNATURES_H__
#define __IPS_SIGNATURES_H__

#include <vector>

#include "config.h"
#include "i_first_tier_agg.h"
#include "ips_entry.h"
#include "ips_enums.h"
#include "log_generator.h"
#include "parsed_context.h"
#include "pm_hook.h"

/// \namespace IPSSignatureSubTypes
/// \brief Namespace containing subtypes for IPS signatures.
namespace IPSSignatureSubTypes
{
using ActionResults = std::tuple<IPSSignatureSubTypes::SignatureAction, std::string, std::vector<std::string>>;

/// \class BaseSignature
/// \brief Represents the base signature class.
class BaseSignature
{
public:
    /// \enum MatchType
    /// \brief Enumerates the types of matches for BaseSignature.
    enum class MatchType
    {
        NO_MATCH,
        CACHE_MATCH,
        MATCH
    };

    /// \brief Get the ID of the signature.
    virtual const std::string &getSigId() const = 0;

    /// \brief Get the match type for the signature.
    /// \param matched The set of patterns that matched.
    virtual MatchType getMatch(const std::set<PMPattern> &matched) const = 0;

    /// \brief Get the set of patterns in the signature.
    virtual std::set<PMPattern> patternsInSignature() const = 0;

    /// \brief Get the context of the signature.
    virtual const std::vector<std::string> &getContext() const = 0;
};

/// \class IPSSignatureMetaData
/// \brief Represents the metadata for an IPS signature.
class IPSSignatureMetaData
{
public:
    /// \brief Load the metadata from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Set the indicators for the metadata.
    /// \param source The source indicator.
    /// \param version The version indicator.
    void setIndicators(const std::string &source, const std::string &version);

    /// \brief Get the ID of the signature.
    const std::string &
    getId() const
    {
        return protection_id;
    }

    /// \brief Get the name of the signature.
    const std::string &
    getName() const
    {
        return sig_name;
    }

    /// \brief Get the update version of the signature.
    const std::string &
    getUpdateVersion() const
    {
        return update;
    }

    /// \brief Get the log title of the signature.
    const std::string &
    getLogTitle() const
    {
        return event_log;
    }

    /// \brief Get the source indicator of the signature.
    const std::string &
    getSource() const
    {
        return source;
    }

    /// \brief Get the feed version of the signature.
    const std::string &
    getFeedVersion() const
    {
        return version;
    }

    /// \brief Get the CVE list of the signature.
    const std::vector<std::string> &
    getCveList() const
    {
        return cve_list;
    }

    /// \brief Get the severity level of the signature.
    IPSLevel
    getSeverity() const
    {
        return severity;
    }

    /// \brief Get the severity level as a string of the signature.
    std::string getSeverityString() const;

    /// \brief Get the confidence level of the signature.
    IPSLevel
    getConfidence() const
    {
        return confidence;
    }

    /// \brief Get the confidence level as a string of the signature.
    std::string getConfidenceString() const;

    /// \brief Get the performance level of the signature.
    IPSLevel
    getPerformance() const
    {
        return performance;
    }

    /// \brief Get the performance level as a string of the signature.
    std::string getPerformanceString() const;

    /// \brief Check if the signature is silent.
    bool
    isSilent() const
    {
        return is_silent;
    }

    /// \brief Get the incident type of the signature.
    std::string getIncidentType() const;

    /// \brief Check if the signature is from a specific year or later.
    /// \param year The year to compare with.
    bool isYearAtLeast(const Maybe<int> &year) const;

    /// \brief Get the year of the signature.
    Maybe<int> getYear() const;

private:
    std::string protection_id;
    std::string sig_name;
    std::string event_log;
    std::string update;
    std::string source;
    std::string version;
    std::vector<std::string> cve_list;
    std::vector<std::string> tag_list;
    IPSLevel severity;
    IPSLevel confidence;
    IPSLevel performance;
    bool is_silent = false;
};

/// \class CompleteSignature
/// \brief Represents a complete signature.
class CompleteSignature
{
public:
    /// \brief Load the complete signature from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Get the match type for the signature.
    /// \param matches The set of patterns that matched.
    BaseSignature::MatchType getMatch(const std::set<PMPattern> &matches) const;

    /// \brief Get the set of patterns in the signature.
    std::set<PMPattern> patternsInSignature() const;

    /// \brief Set the indicators for the complete signature.
    /// \param source The source indicator.
    /// \param version The version indicator.
    void setIndicators(const std::string &source, const std::string &version);

    /// \brief Get the context of the signature.
    const std::vector<std::string> &
    getContext() const
    {
        return rule->getContext();
    }

    /// \brief Get the ID of the signature.
    const std::string &
    getId() const
    {
        return metadata.getId();
    }

    /// \brief Get the log title of the signature.
    const std::string &
    getLogTitle() const
    {
        return metadata.getLogTitle();
    }

    /// \brief Get the name of the signature.
    const std::string &
    getName() const
    {
        return metadata.getName();
    }

    /// \brief Get the update version of the signature.
    const std::string &
    getUpdateVersion() const
    {
        return metadata.getUpdateVersion();
    }

    /// \brief Get the source indicator of the signature.
    const std::string &
    getSource() const
    {
        return metadata.getSource();
    }

    /// \brief Get the feed version of the signature.
    const std::string &
    getFeedVersion() const
    {
        return metadata.getFeedVersion();
    }

    /// \brief Get the CVE list of the signature.
    const std::vector<std::string> &
    getCveList() const
    {
        return metadata.getCveList();
    }

    /// \brief Get the severity level of the signature.
    IPSLevel
    getSeverity() const
    {
        return metadata.getSeverity();
    }

    /// \brief Get the severity level as a string of the signature.
    std::string
    getSeverityString() const
    {
        return metadata.getSeverityString();
    }

    /// \brief Get the confidence level of the signature.
    IPSLevel
    getConfidence() const
    {
        return metadata.getConfidence();
    }

    /// \brief Get the confidence level as a string of the signature.
    std::string
    getConfidenceString() const
    {
        return metadata.getConfidenceString();
    }

    /// \brief Get the performance level of the signature.
    IPSLevel
    getPerformance() const
    {
        return metadata.getPerformance();
    }

    /// \brief Get the performance level as a string of the signature.
    std::string
    getPerformanceString() const
    {
        return metadata.getPerformanceString();
    }

    /// \brief Check if the signature is silent.
    bool
    isSilent() const
    {
        return metadata.isSilent();
    }

    /// \brief Get the incident type of the signature.
    std::string
    getIncidentType() const
    {
        return metadata.getIncidentType();
    }

    /// \brief Check if the signature is from a specific year or later.
    /// \param year The year to compare with.
    bool
    isYearAtLeast(const Maybe<int> &year) const
    {
        return metadata.isYearAtLeast(year);
    }

    /// \brief Get the year of the signature.
    Maybe<int>
    getYear() const
    {
        return metadata.getYear();
    }

private:
    IPSSignatureMetaData metadata;
    std::shared_ptr<BaseSignature> rule;
};

/// \class SignatureAndAction
/// \brief Represents a signature and its associated action.
class SignatureAndAction
{
public:
    /// \brief Construct a SignatureAndAction object.
    /// \param _signature The complete signature.
    /// \param _action The signature action.
    SignatureAndAction(std::shared_ptr<CompleteSignature> _signature, SignatureAction _action) :
        signature(_signature), action(_action)
    {}

    /// \brief Check if the signature is matched for prevention.
    /// \param context_buffer The context buffer.
    /// \param pattern The set of patterns to match.
    bool isMatchedPrevent(const Buffer &context_buffer, const std::set<PMPattern> &pattern) const;

    /// \brief Check if the signature is matched silently.
    /// \param context_buffer The context buffer.
    bool matchSilent(const Buffer &context_buffer) const;

    /// \brief Get the set of patterns in the signature.
    std::set<PMPattern>
    patternsInSignature() const
    {
        return signature->patternsInSignature();
    }

    /// \brief Get the context of the signature.
    const std::vector<std::string> &
    getContext() const
    {
        return signature->getContext();
    }

private:
    /// \brief Get the action results for the IPS state.
    /// \param ips_state The IPS entry.
    ActionResults getAction(const IPSEntry &ips_state) const;

    std::shared_ptr<CompleteSignature> signature;
    SignatureAction action;
};
} // namespace IPSSignatureSubTypes

/// \class IPSSignaturesPerContext
/// \brief Represents IPS signatures per context.
class IPSSignaturesPerContext : public Singleton::Consume<I_FirstTierAgg>
{
public:
    /// \brief Add a signature to the context.
    /// \param sig The signature and its associated action.
    void addSignature(const IPSSignatureSubTypes::SignatureAndAction &sig);

    /// \brief Check if the context is matched for prevention.
    /// \param context_buffer The context buffer.
    bool isMatchedPrevent(const Buffer &context_buffer) const;

    /// \brief Calculate the first tier for the given context name.
    /// \param ctx_name The context name.
    void calcFirstTier(const std::string &ctx_name);

private:
    /// \brief Get the first tier matches for the buffer.
    /// \param buffer The buffer to match.
    std::set<PMPattern> getFirstTierMatches(const Buffer &buffer) const;

    std::map<PMPattern, std::vector<IPSSignatureSubTypes::SignatureAndAction>> signatures_per_lss;
    std::vector<IPSSignatureSubTypes::SignatureAndAction> signatures_without_lss;
    std::shared_ptr<PMHook> first_tier;
};

/// \class IPSSignaturesResource
/// \brief Represents IPS signatures resource.
class IPSSignaturesResource
{
public:
    /// \brief Load the IPS signatures resource from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Get all the signatures.
    /// \return A vector of shared pointers to CompleteSignature.
    const std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> &
    getSignatures() const
    {
        return all_signatures;
    }

private:
    std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> all_signatures;
};

/// \class SnortSignaturesResourceFile
/// \brief Represents Snort signatures resource file.
class SnortSignaturesResourceFile
{
public:
    /// \brief Load the Snort signatures resource file from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Check if the file name matches.
    /// \param file_name The name of the file.
    /// \return True if the file name matches, otherwise false.
    bool
    isFile(const std::string &file_name) const
    {
        return file_name == name;
    }

    /// \brief Get all the signatures.
    /// \return A vector of shared pointers to CompleteSignature.
    const std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> &
    getSignatures() const
    {
        return all_signatures;
    }

private:
    std::string name;
    std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> all_signatures;
};

/// \class SnortSignaturesResource
/// \brief Represents Snort signatures resource.
class SnortSignaturesResource
{
public:
    /// \brief Load the Snort signatures resource from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Get all the signatures for the given file name.
    /// \param file_name The name of the file.
    /// \return A vector of shared pointers to CompleteSignature.
    const std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> &
    getSignatures(const std::string &file_name) const
    {
        for (auto &file : files) {
            if (file.isFile(file_name)) return file.getSignatures();
        }
        return empty;
    }

private:
    std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> empty;
    std::vector<SnortSignaturesResourceFile> files;
};

/// \class IPSSignatures
/// \brief Represents IPS signatures.
class IPSSignatures
{
    std::set<PMPattern> getFirstTier(const ParsedContext &context);

public:
    /// \brief Load the IPS signatures from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Check if the context is matched for prevention.
    /// \param context_name The name of the context.
    /// \param context_buffer The context buffer.
    bool isMatchedPrevent(const std::string &context_name, const Buffer &context_buffer) const;

    /// \brief Check if the IPS signatures are empty.
    /// \return True if the signatures are empty, otherwise false.
    bool
    isEmpty() const
    {
        return signatures_per_context.empty();
    }

    /// \brief Check if the IPS signatures for the given context are empty.
    /// \param context The name of the context.
    /// \return True if the signatures for the context are empty, otherwise false.
    bool isEmpty(const std::string &context) const;

    /// \brief Get the asset name.
    /// \return The asset name.
    const std::string &
    getAsset() const
    {
        return asset_name;
    }

    /// \brief Get the asset ID.
    /// \return The asset ID.
    const std::string &
    getAssetId() const
    {
        return asset_id;
    }

    /// \brief Get the practice name.
    /// \return The practice name.
    const std::string &
    getPractice() const
    {
        return practice_name;
    }

    /// \brief Get the practice ID.
    /// \return The practice ID.
    const std::string &
    getPracticeId() const
    {
        return practice_id;
    }

    /// \brief Get the source identifier.
    /// \return The source identifier.
    const std::string &
    getSourceIdentifier() const
    {
        return source_id;
    }

private:
    std::map<std::string, IPSSignaturesPerContext> signatures_per_context;
    std::string asset_name;
    std::string asset_id;
    std::string practice_name;
    std::string practice_id;
    std::string source_id;
};

/// \class SnortSignatures
/// \brief Represents Snort signatures.
class SnortSignatures
{
    std::set<PMPattern> getFirstTier(const ParsedContext &context);

public:
    /// \brief Load the Snort signatures from a JSON archive.
    /// \param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar);

    /// \brief Check if the context is matched for prevention.
    /// \param context_name The name of the context.
    /// \param context_buffer The context buffer.
    bool isMatchedPrevent(const std::string &context_name, const Buffer &context_buffer) const;

    /// \brief Check if the Snort signatures are empty.
    /// \return True if the signatures are empty, otherwise false.
    bool
    isEmpty() const
    {
        return signatures_per_context.empty();
    }

    /// \brief Check if the Snort signatures for the given context are empty.
    /// \param context The name of the context.
    /// \return True if the signatures for the context are empty, otherwise false.
    bool isEmpty(const std::string &context) const;

    /// \brief Get the asset name.
    /// \return The asset name.
    const std::string &
    getAsset() const
    {
        return asset_name;
    }

    /// \brief Get the asset ID.
    /// \return The asset ID.
    const std::string &
    getAssetId() const
    {
        return asset_id;
    }

    /// \brief Get the practice name.
    /// \return The practice name.
    const std::string &
    getPractice() const
    {
        return practice_name;
    }

    /// \brief Get the practice ID.
    /// \return The practice ID.
    const std::string &
    getPracticeId() const
    {
        return practice_id;
    }

    /// \brief Get the source identifier.
    /// \return The source identifier.
    const std::string &
    getSourceIdentifier() const
    {
        return source_id;
    }

private:
    std::map<std::string, IPSSignaturesPerContext> signatures_per_context;
    std::string asset_name;
    std::string asset_id;
    std::string practice_name;
    std::string practice_id;
    std::string source_id;
};

#endif // __IPS_SIGNATURES_H__
