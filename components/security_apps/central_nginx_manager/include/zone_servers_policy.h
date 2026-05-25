#ifndef CENTRAL_NGINX_CERTIFICATE_H
#define CENTRAL_NGINX_CERTIFICATE_H

#include <string>
#include <cereal/types/string.hpp>
#include <cereal/archives/json.hpp>

#include "debug.h"
#include "downloaded_certificate.h"

USE_DEBUG_FLAG(D_NGINX_MANAGER);

class CertificateParams {
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try
        {
            ar(cereal::make_nvp("id", id));
            ar(cereal::make_nvp("fullChainPath", public_key_location));
            ar(cereal::make_nvp("privateKeyPath", private_key_location));
            ar(cereal::make_nvp("certificateId", certificate_id));
            dbgWarning(D_NGINX_MANAGER)
                << "Loaded CertificateParams with id: "
                << certificate_id;
        }
        catch(const std::exception& e)
        {
            dbgWarning(D_NGINX_MANAGER) << "Failed to load single CertificateParams JSON config. Error: " << e.what();
            ar.setNextName(nullptr);
        }
    }
    const std::string &getCertificateId() const { return certificate_id; }
    const std::string &getPublicKeyLocation() const { return public_key_location; }
    const std::string &getPrivateKeyLocation() const { return private_key_location; }
private:
    std::string id;
    std::string public_key_location;
    std::string private_key_location;
    std::string certificate_id;
};

class CertificatePolicy {
public:

    const std::string &getId() const { return id; }
    const std::vector<std::string> &getDomains() const { return domains; }
    const CertificateParams &getCertificate() const { return certificate; }

    void load(cereal::JSONInputArchive &ar)
    {
        try
        {
            ar(cereal::make_nvp("certificate", certificate));
            dbgWarning(D_NGINX_MANAGER)
                << "Loaded CertificatePolicy with certificate id: "
                << certificate.getCertificateId();
        }
        catch(const std::exception& e)
        {
            dbgWarning(D_NGINX_MANAGER) << "Failed to load single CertificatePolicy JSON config. Error: " << e.what();
        }

    }

private:
    std::string id;
    std::vector<std::string> domains;
    CertificateParams certificate;
};

class Servers
{
private:
    std::vector<CertificatePolicy> certificates;
public:
    void load(cereal::JSONInputArchive &archive_in)
    {
        cereal::load(archive_in, certificates);
    }

    const std::vector<CertificatePolicy> & getCertificates() const { return certificates; }
};

#endif // CENTRAL_NGINX_CERTIFICATE_H
