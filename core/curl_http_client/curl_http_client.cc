#include "curl_http_client.h"

#include <iostream>

#include "debug.h"
#include "messaging/messaging_enums.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_MANAGER);

// Helper function to convert HTTP status code to HTTPStatusCode enum
HTTPStatusCode convertStatusCode(long code)
{
    switch (code) {
        case 200: return HTTPStatusCode::HTTP_OK;
        case 204: return HTTPStatusCode::HTTP_NO_CONTENT;
        case 207: return HTTPStatusCode::HTTP_MULTI_STATUS;
        case 400: return HTTPStatusCode::HTTP_BAD_REQUEST;
        case 401: return HTTPStatusCode::HTTP_UNAUTHORIZED;
        case 403: return HTTPStatusCode::HTTP_FORBIDDEN;
        case 404: return HTTPStatusCode::HTTP_NOT_FOUND;
        case 405: return HTTPStatusCode::HTTP_METHOD_NOT_ALLOWED;
        case 407: return HTTPStatusCode::HTTP_PROXY_AUTHENTICATION_REQUIRED;
        case 408: return HTTPStatusCode::HTTP_REQUEST_TIME_OUT;
        case 413: return HTTPStatusCode::HTTP_PAYLOAD_TOO_LARGE;
        case 429: return HTTPStatusCode::HTTP_TOO_MANY_REQUESTS;
        case 500: return HTTPStatusCode::HTTP_INTERNAL_SERVER_ERROR;
        case 501: return HTTPStatusCode::HTTP_NOT_IMPLEMENTED;
        case 502: return HTTPStatusCode::HTTP_BAD_GATEWAY;
        case 503: return HTTPStatusCode::HTTP_SERVICE_UNABAILABLE;
        case 504: return HTTPStatusCode::HTTP_GATEWAY_TIMEOUT;
        case 505: return HTTPStatusCode::HTTP_VERSION_NOT_SUPPORTED;
        case 506: return HTTPStatusCode::HTTP_VARIANT_ALSO_NEGOTIATES;
        case 507: return HTTPStatusCode::HTTP_INSUFFICIENT_STORAGE;
        case 508: return HTTPStatusCode::HTTP_LOOP_DETECTED;
        case 510: return HTTPStatusCode::HTTP_NOT_EXTENDED;
        case 511: return HTTPStatusCode::HTTP_NETWORK_AUTHENTICATION_REQUIRED;
        default: return HTTPStatusCode::NO_HTTP_RESPONSE;
    }
}

CurlHttpClient::CurlHttpClient(): auth_enabled(false)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

CurlHttpClient::~CurlHttpClient()
{
    curl_global_cleanup();
}

void
CurlHttpClient::setProxy(const string& hosts)
{
    no_proxy_hosts = hosts;
}

void
CurlHttpClient::setBasicAuth(const string& username, const string& password)
{
    this->username = username;
    this->password = password;
}

void
CurlHttpClient::authEnabled(bool enabled)
{
    auth_enabled = enabled;
}

HTTPResponse
CurlHttpClient::get(const string& url, const map<string, string>& headers)
{
    return perform_request("GET", url, "", headers);
}

HTTPResponse
CurlHttpClient::post(const string& url, const string& data, const map<string, string>& headers)
{
    return perform_request("POST", url, data, headers);
}

HTTPResponse
CurlHttpClient::put(const string& url, const string& body, const map<string, string>& headers)
{
    return perform_request("PUT", url, body, headers);
}

HTTPResponse
CurlHttpClient::patch(const string& url, const string& body, const map<string, string>& headers)
{
    return perform_request("PATCH", url, body, headers);
}

HTTPResponse
CurlHttpClient::del(const string& url, const map<string, string>& headers)
{
    return perform_request("DELETE", url, "", headers);
}

size_t
CurlHttpClient::WriteCallback(void *contents, size_t size, size_t nmemb, string *userp)
{
    size_t totalSize = size * nmemb;
    userp->append(static_cast<char *>(contents), totalSize);
    return totalSize;
}

HTTPResponse
CurlHttpClient::perform_request(
    const string& method,
    const string& url,
    const string& body,
    const map<string, string>& headers
)
{
    string response_body;
    long status_code = 0;
    CURL *curl = curl_easy_init();
    if (!curl) {
        return HTTPResponse(HTTPStatusCode::NO_HTTP_RESPONSE, "Failed to initialize curl");
    }

    struct curl_slist *header_list = nullptr;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    if (!no_proxy_hosts.empty()) {
        dbgTrace(D_NGINX_MANAGER) << "Using proxy url: " << no_proxy_hosts;
        curl_easy_setopt(curl, CURLOPT_PROXY, no_proxy_hosts.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (!username.empty() && !password.empty() && auth_enabled) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
    }

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    } else if (method == "PATCH") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    for (const auto &header_pair : headers) {
        string header_str = header_pair.first + ": " + header_pair.second;
        header_list = curl_slist_append(header_list, header_str.c_str());
    }
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    } else {
        response_body = "curl_easy_perform() failed: " + string(curl_easy_strerror(res));
        status_code = 0;
    }

    if (header_list) {
        curl_slist_free_all(header_list);
    }
    curl_easy_cleanup(curl);

    return HTTPResponse(convertStatusCode(status_code), response_body);
}
