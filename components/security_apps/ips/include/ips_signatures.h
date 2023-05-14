#ifndef __IPS_SIGNATURES_H__
#define __IPS_SIGNATURES_H__

#include <vector>

#include "config.h"
#include "parsed_context.h"
#include "log_generator.h"
#include "pm_hook.h"
#include "ips_enums.h"
#include "ips_entry.h"
#include "i_first_tier_agg.h"

namespace IPSSignatureSubTypes
{
using ActionResults = std::tuple<IPSSignatureSubTypes::SignatureAction, std::string, std::vector<std::string>>;

class BaseSignature
{
public:
    enum class MatchType { NO_MATCH, CACHE_MATCH, MATCH };

    virtual const std::string & getSigId() const = 0;
    virtual MatchType getMatch(const std::set<PMPattern> &matched) const = 0;
    virtual std::set<PMPattern> patternsInSignature() const = 0;
    virtual const std::vector<std::string> & getContext() const = 0;
};

class IPSSignatureMetaData
{
public:
    void load(cereal::JSONInputArchive &ar);
    void setIndicators(const std::string &source, const std::string &version);

    const std::string & getId()                   const { return protection_id; }
    const std::string & getName()                 const { return sig_name; }
    const std::string & getUpdateVersion()        const { return update; }
    const std::string & getLogTitle()             const { return event_log; }
    const std::string & getSource()               const { return source; }
    const std::string & getFeedVersion()          const { return version; }
    const std::vector<std::string> & getCveList() const { return cve_list; }
    IPSLevel getSeverity()                        const { return severity; }
    std::string getSeverityString()               const;
    IPSLevel getConfidence()                      const { return confidence; }
    std::string getConfidenceString()             const;
    IPSLevel getPerformance()                     const { return performance; }
    std::string getPerformanceString()            const;
    bool isSilent()                               const { return is_silent; }
    std::string getIncidentType()                 const;
    bool isYearAtLeast(const Maybe<int> &year)    const;
    Maybe<int> getYear()                          const;

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

class CompleteSignature
{
public:
    void load(cereal::JSONInputArchive &ar);
    BaseSignature::MatchType getMatch(const std::set<PMPattern> &matches) const;
    std::set<PMPattern> patternsInSignature() const;
    void setIndicators(const std::string &source, const std::string &version);

    const std::vector<std::string> & getContext() const { return rule->getContext(); }
    const std::string & getId()                   const { return metadata.getId(); }
    const std::string & getLogTitle()             const { return metadata.getLogTitle(); }
    const std::string & getName()                 const { return metadata.getName(); }
    const std::string & getUpdateVersion()        const { return metadata.getUpdateVersion(); }
    const std::string & getSource()               const { return metadata.getSource(); }
    const std::string & getFeedVersion()          const { return metadata.getFeedVersion(); }
    const std::vector<std::string> & getCveList() const { return metadata.getCveList(); }
    IPSLevel getSeverity()                        const { return metadata.getSeverity(); }
    std::string getSeverityString()               const { return metadata.getSeverityString(); }
    IPSLevel getConfidence()                      const { return metadata.getConfidence(); }
    std::string getConfidenceString()             const { return metadata.getConfidenceString(); }
    IPSLevel getPerformance()                     const { return metadata.getPerformance(); }
    std::string getPerformanceString()            const { return metadata.getPerformanceString(); }
    bool isSilent()                               const { return metadata.isSilent(); }
    std::string getIncidentType()                 const { return metadata.getIncidentType(); }

    bool isYearAtLeast(const Maybe<int> &year)    const { return metadata.isYearAtLeast(year); }
    Maybe<int> getYear()                          const { return metadata.getYear(); }

private:
    IPSSignatureMetaData metadata;
    std::shared_ptr<BaseSignature> rule;
};

class SignatureAndAction
{
public:
    SignatureAndAction(std::shared_ptr<CompleteSignature> _signature, SignatureAction _action)
            :
        signature(_signature),
        action(_action)
    {
    }

    bool isMatchedPrevent(const Buffer &context_buffer, const std::set<PMPattern> &pattern) const;
    bool matchSilent(const Buffer &context_buffer) const;
    std::set<PMPattern> patternsInSignature() const { return signature->patternsInSignature(); }
    const std::vector<std::string> & getContext() const { return signature->getContext(); }

private:
    ActionResults getAction(const IPSEntry &ips_state) const;
    std::shared_ptr<CompleteSignature> signature;
    SignatureAction action;
};
} // IPSSignatureSubTypes

class IPSSignaturesPerContext : public Singleton::Consume<I_FirstTierAgg>
{
public:
    void addSignature(const IPSSignatureSubTypes::SignatureAndAction &sig);
    bool isMatchedPrevent(const Buffer &context_buffer) const;
    void calcFirstTier(const std::string &ctx_name);

private:
    std::set<PMPattern> getFirstTierMatches(const Buffer &buffer) const;

    std::map<PMPattern, std::vector<IPSSignatureSubTypes::SignatureAndAction>> signatures_per_lss;
    std::vector<IPSSignatureSubTypes::SignatureAndAction> signatures_without_lss;
    std::shared_ptr<PMHook> first_tier;
};

class IPSSignaturesResource
{
public:
    void load(cereal::JSONInputArchive &ar);

    const std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> &
    getSignatures() const
    {
        return all_signatures;
    }

private:
    std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> all_signatures;
};

class SnortSignaturesResourceFile
{
public:
    void load(cereal::JSONInputArchive &ar);
    bool isFile(const std::string &file_name) const { return file_name == name; }
    const std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> &
    getSignatures() const
    {
        return all_signatures;
    }

private:
    std::string name;
    std::vector<std::shared_ptr<IPSSignatureSubTypes::CompleteSignature>> all_signatures;
};

class SnortSignaturesResource
{
public:
    void load(cereal::JSONInputArchive &ar);

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

class IPSSignatures
{
    std::set<PMPattern> getFirstTier(const ParsedContext &context);

public:
    void load(cereal::JSONInputArchive &ar);
    bool isMatchedPrevent(const std::string &context_name, const Buffer &context_buffer) const;
    bool isEmpty() const { return signatures_per_context.empty(); }
    bool isEmpty(const std::string &context) const;

    const std::string & getAsset() const { return asset_name; }
    const std::string & getAssetId() const { return asset_id; }
    const std::string & getPractice() const { return practice_name; }
    const std::string & getPracticeId() const { return practice_id; }
    const std::string & getSourceIdentifier() const { return source_id; }

private:
    std::map<std::string, IPSSignaturesPerContext> signatures_per_context;
    std::string asset_name;
    std::string asset_id;
    std::string practice_name;
    std::string practice_id;
    std::string source_id;
};

class SnortSignatures
{
    std::set<PMPattern> getFirstTier(const ParsedContext &context);

public:
    void load(cereal::JSONInputArchive &ar);
    bool isMatchedPrevent(const std::string &context_name, const Buffer &context_buffer) const;
    bool isEmpty() const { return signatures_per_context.empty(); }
    bool isEmpty(const std::string &context) const;

    const std::string & getAsset() const { return asset_name; }
    const std::string & getAssetId() const { return asset_id; }
    const std::string & getPractice() const { return practice_name; }
    const std::string & getPracticeId() const { return practice_id; }
    const std::string & getSourceIdentifier() const { return source_id; }

private:
    std::map<std::string, IPSSignaturesPerContext> signatures_per_context;
    std::string asset_name;
    std::string asset_id;
    std::string practice_name;
    std::string practice_id;
    std::string source_id;
};

#endif // __IPS_SIGNATURES_H__
