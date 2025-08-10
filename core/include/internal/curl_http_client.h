#ifndef __CURL_HTTP_CLIENT_H__
#define __CURL_HTTP_CLIENT_H__

#include <string>
#include <vector>
#include <map>
#include <curl/curl.h>
#include "messaging/http_response.h"
#include "i_http_client.h"

class CurlHttpClient : public I_HttpClient
{
public:
    CurlHttpClient();
    ~CurlHttpClient();

    void setProxy(const std::string& hosts) override;
    void setBasicAuth(const std::string& username, const std::string& password) override;
    void authEnabled(bool enabled) override;

    HTTPResponse
    get(
        const std::string& url,
        const std::map<std::string, std::string>& headers = {}
    ) override;

    HTTPResponse
    post(
        const std::string& url,
        const std::string& data,
        const std::map<std::string, std::string>& headers = {}
    ) override;

    HTTPResponse
    put(
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}
    ) override;    HTTPResponse
    patch(
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}
    ) override;

    HTTPResponse
    del(
        const std::string& url,
        const std::map<std::string, std::string>& headers = {}
    ) override;

private:
    static size_t
    WriteCallback(
        void *contents,
        size_t size,
        size_t nmemb,
        std::string *userp
    );

    HTTPResponse
    perform_request(
        const std::string& method,
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers
    );

    std::string no_proxy_hosts;
    bool auth_enabled;
    std::string username;
    std::string password;
};

#endif // __CURL_HTTP_CLIENT_H__

