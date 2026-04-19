#ifndef __DOWNLOADED_CERTIFICATE_H__
#define __DOWNLOADED_CERTIFICATE_H__

#include <string>
#include <map>
#include <vector>
#include <cereal/types/string.hpp>
#include <cereal/types/map.hpp>
#include <cereal/archives/json.hpp>

#include "debug.h"
#include "package.h"
#include "rest.h"

USE_DEBUG_FLAG(D_NGINX_MANAGER);

class CertificateBatchRequest : public ClientRest
{
public:
    explicit CertificateBatchRequest(const std::vector<std::string> &ids) : certificate_ids(ids) {}
    C2S_LABEL_PARAM(std::vector<std::string>, certificate_ids, "certificateIds");
};

class CNMCertificate
{
public:
    std::string getPublicKey() const { return public_key; }
    std::string getPrivateKey() const { return private_key; }
    std::string getChain() const { return chain; }
    std::string getCertificateId() const { return certificate_id; }
    void setCertificateId(const std::string &id) { certificate_id = id; }
    std::string getVersion() const { return version; }
    void setVersion(const std::string &v) { version = v; }

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(
            cereal::make_nvp("publicKey", public_key),
            cereal::make_nvp("privateKey", private_key),
            cereal::make_nvp("chain", chain)
        );

        try {
            ar(cereal::make_nvp("id", certificate_id));
        } catch (const std::exception &) {
            dbgWarning(D_NGINX_MANAGER) << "Downloaded cert missing 'id' field, defaulting to empty.";
            ar.setNextName(nullptr);
        }

        try {
            ar(cereal::make_nvp("version", version));
        } catch (const std::exception &) {
            // Older files may not include version; leave empty.
            ar.setNextName(nullptr);
        }
    }

private:
    std::string public_key;
    std::string private_key;
    std::string chain;
    std::string certificate_id;
    std::string version;
};

// enum class ChecksumTypes { SHA1, SHA256, SHA512, MD5 };

static const std::map<std::string, Package::ChecksumTypes> checksum_map = {
    { "sha1sum",   Package::ChecksumTypes::SHA1 },
    { "sha256sum", Package::ChecksumTypes::SHA256 },
    { "sha512sum", Package::ChecksumTypes::SHA512 },
    { "md5sum",    Package::ChecksumTypes::MD5 }
};

class Certificate {
public:
    const std::string &getId() const { return certificate_id; }
    const std::string &getFingerprint() const { return fingerprint; }
    const std::string &getDownloadPath() const { return download_path; }
    const std::string &getChecksum() const { return checksum; }
    Package::ChecksumTypes getChecksumType() const { return checksum_type; }
    const std::string &getVersion() const { return version; }
    const std::string &getSize() const { return size; }

    template<class Archive>
    void serialize(Archive & ar)
    {
        std::string checksum_type_as_string;
        ar(
            cereal::make_nvp("certificateId", certificate_id),
            cereal::make_nvp("fingerprint", fingerprint),
            cereal::make_nvp("downloadPath", download_path),
            cereal::make_nvp("checksum", checksum),
            cereal::make_nvp("checksumType", checksum_type_as_string),
            cereal::make_nvp("version", version),
            cereal::make_nvp("size", size)
        );
        if (checksum_map.find(checksum_type_as_string) != checksum_map.end()) {
            checksum_type = checksum_map.at(checksum_type_as_string);
        } else {
            checksum_type = Package::ChecksumTypes::SHA256; // default
        }
    }
private:
    std::string certificate_id;
    std::string fingerprint;
    std::string download_path;
    std::string checksum;
    Package::ChecksumTypes checksum_type = Package::ChecksumTypes::SHA256;
    std::string version;
    std::string size;
};

#endif // __DOWNLOADED_CERTIFICATE_H__
