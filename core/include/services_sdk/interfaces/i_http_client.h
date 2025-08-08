#ifndef __I_HTTP_CLIENT_H__
#define __I_HTTP_CLIENT_H__

#include <string>
#include <map>
#include "messaging/http_response.h"

class I_HttpClient
{
public:
    virtual ~I_HttpClient() = default;
    virtual void setProxy(const std::string& hosts) = 0;
    virtual void setBasicAuth(const std::string& username, const std::string& password) = 0;
    virtual void authEnabled(bool enabled) = 0;

    virtual HTTPResponse
    get(
        const std::string& url,
        const std::map<std::string, std::string>& headers = {}
    ) = 0;

    virtual HTTPResponse
    post(
        const std::string& url,
        const std::string& data,
        const std::map<std::string, std::string>& headers = {}
    ) = 0;

    virtual HTTPResponse
    put(
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}
    ) = 0;

    virtual HTTPResponse
    patch(
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}
    ) = 0;

    virtual HTTPResponse
    del(
        const std::string& url,
        const std::map<std::string, std::string>& headers = {}
    ) = 0;
};

#endif // __I_HTTP_CLIENT_H__
