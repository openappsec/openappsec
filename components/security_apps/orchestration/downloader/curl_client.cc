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

#include "curl_client.h"

#include <curl/curl.h>
#if defined(alpine)
#include <openssl/ossl_typ.h>
#else
#include <openssl/types.h>
#endif //ifdef alpine
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <memory>
#include <algorithm>

#include "config.h"
#include "url_parser.h"
#include "debug.h"
#include "scope_exit.h"

USE_DEBUG_FLAG(D_HTTP_REQUEST);

using namespace std;

// LCOV_EXCL_START Reason: Depends on real download server.

class CurlGlobalInit
{
public:
    CurlGlobalInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobalInit() { curl_global_cleanup(); }
};
static CurlGlobalInit global_curl_handle;

HttpCurl::HttpCurl(
    const URLParser &_url,
    ofstream &_out_file,
    const string &_bearer,
    const Maybe<string> &proxy_url,
    const Maybe<uint16_t> &proxy_port,
    const Maybe<string> &proxy_auth)
            :
        url(_url),
        out_file(_out_file),
        bearer(_bearer),
        curl(unique_ptr<CURL, function<void(CURL *)>>(curl_easy_init(), curl_easy_cleanup))
{
    string port = url.getPort();
    if (!port.empty())
    {
        curl_url = url.getBaseURL().unpack() + ":" + port + url.getQuery();
    } else
    {
        curl_url = url.getBaseURL().unpack() + url.getQuery();
    }

    if (proxy_url.ok())
    {
        //Update curl proxy
        if (!proxy_port.ok())
        {
            dbgWarning(D_HTTP_REQUEST)
                << "Invalid proxy port, CURL default port will be used instead. Error: "
                << proxy_port.getErr();
            proxy = proxy_url.unpack();
        } else
        {
            proxy = proxy_url.unpack() + ":" + to_string(proxy_port.unpack());
        }
    }
    if (proxy_auth.ok())
    {
        I_Encryptor *encryptor = Singleton::Consume<I_Encryptor>::by<HttpCurl>();
        proxy_credentials = "Proxy-Authorization: Basic " + encryptor->base64Encode(proxy_auth.unpack());
    }
}

HttpCurl::HttpCurl(const HttpCurl &other)
        :
    url(other.url),
    out_file(other.out_file),
    bearer(other.bearer),
    proxy(other.proxy),
    proxy_credentials(other.proxy_credentials),
    curl(unique_ptr<CURL, function<void(CURL *)>>(curl_easy_init(), curl_easy_cleanup))
    {
    }

void
HttpCurl::setCurlOpts(long timeout, HTTP_VERSION http_version)
{
    struct curl_slist *headers = NULL;
    struct curl_slist *proxy_headers = NULL;
    CURL *curl_handle = curl.get();

    //HTTP options
    curl_easy_setopt(curl_handle, CURLOPT_HTTP_VERSION, http_version);

    //SSL options
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);

    //Header options
    curl_easy_setopt(curl_handle, CURLOPT_URL, curl_url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writeResponseCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &out_file);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, timeout);
    headers = curl_slist_append(headers, "Accept: */*");
    string auth = string("Authorization: Bearer ") + bearer;
    headers = curl_slist_append(headers, auth.c_str());
    headers = curl_slist_append(headers, "User-Agent: Infinity Next (a7030abf93a4c13)");
    string uuid_header = string("X-Trace-Id: ") + TraceIdGenerator::generateTraceId();
    headers = curl_slist_append(headers, "Connection: close");
    headers = curl_slist_append(headers, uuid_header.c_str());

    //Proxy options
    if (!proxy.empty())
    {
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, proxy.c_str());
        if (!proxy_credentials.empty())
        {
            proxy_headers = curl_slist_append(proxy_headers, proxy_credentials.c_str());
            //Apply proxy headers
            curl_easy_setopt(curl_handle, CURLOPT_PROXYHEADER, proxy_headers);
        }
        dbgTrace(D_HTTP_REQUEST) << "Using Proxy: " << proxy;
    }

    //Apply headers
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
}

bool
HttpCurl::connect()
{
    // Response information.
    long http_code;
    char errorstr[CURL_ERROR_SIZE];
    CURLcode res;
    stringstream response_header;

    CURL *curl_handle = curl.get();

    auto __scope_exit = make_scope_exit(
        [this] () {
            out_file.flush();
            out_file.close();
        }
    );

    //Debug options
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, trace_http_request);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGDATA, static_cast<void*>(&response_header));
    curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorstr);

    // Perform the request, res will get the return code
    res = curl_easy_perform(curl_handle);
    if (res != CURLE_OK) {
        dbgWarning(D_HTTP_REQUEST) << "Failed to perform CURL request. CURL error " << string(errorstr);
        dbgWarning(D_HTTP_REQUEST) << "CURL result " + string(curl_easy_strerror(res));
        print_response_header(response_header);

        return false;
    }

    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200){
        dbgWarning(D_HTTP_REQUEST) << "Failed to connect. Error code: " + to_string(http_code);
        print_response_header(response_header);

        return false;
    }

    dbgTrace(D_HTTP_REQUEST) << "CURL HTTP request successfully completed.";

    return true;
}

int
HttpCurl::trace_http_request(
    CURL *,
    curl_infotype type,
    char *data,
    size_t,
    void *opq)
{
    stringstream *response_header = static_cast<stringstream *>(opq);
    switch (type)
    {
    case CURLINFO_HEADER_OUT:
        dbgTrace(D_HTTP_REQUEST)
            << "=> Sending the following HTTP request:\n"
            << string(data);
        break;
    case CURLINFO_HEADER_IN:
        if (!response_header)
        {
            // Should never reach this if. But just in case.
            // The data will be printed at chunks in this case
            dbgError(D_HTTP_REQUEST)
                << "<= Received the following HTTP response header (should not reach here):\n"
                << string(data);
        } else
        {
            // The response header Will be printed at once later after curl_easy_perform.
            // And after assembling all the response header chunks.
            *response_header << string(data);
        }
        break;
    default:
        return 0;
    }

    return 0;
}

u_int
HttpCurl::writeResponseCallback(
    const char *in_buf,
    uint num_of_messages,
    uint size_of_data,
    ostream out_stream)
{
    const unsigned long total_bytes(num_of_messages * size_of_data);
    out_stream.write(in_buf, total_bytes);
    return total_bytes;
}

void
HttpCurl::print_response_header(stringstream &stream)
{
    string line;
    istringstream header_stream(stream.str());
    stringstream header_lines;
    int lines_to_print = 10;
    int i = 0;

    while (getline(header_stream, line) && i < lines_to_print) {
        header_lines << line << '\n';
        ++i;
    }

    dbgWarning(D_HTTP_REQUEST)
        << "<= Received the following HTTP response header:\n"
        << header_lines.str();
}

HttpsCurl::HttpsCurl(
    const URLParser &_url,
    ofstream &_out_file,
    const string &_bearer,
    const Maybe<string> &proxy_url,
    const Maybe<uint16_t> &proxy_port,
    const Maybe<string> &proxy_auth,
    const string &_ca_path) :
        HttpCurl(_url, _out_file, _bearer, proxy_url, proxy_port, proxy_auth),
        ca_path(_ca_path) {}

HttpsCurl::HttpsCurl(const HttpsCurl &other) :
    HttpCurl(other),
    ca_path(other.ca_path) {}

void
HttpsCurl::setCurlOpts(long timeout, HTTP_VERSION http_version)
{
    struct curl_slist *headers = NULL;
    struct curl_slist *proxy_headers = NULL;
    CURL *curl_handle = curl.get();

    URLProtocol protocol = url.getProtocol();
    if (protocol == URLProtocol::HTTPS)
    {
        if (curl_url.find("https://") == string::npos)
        {
            //Append https://
            curl_url = "https://" + curl_url;
        }
    }

    //HTTP options
    curl_easy_setopt(curl_handle, CURLOPT_HTTP_VERSION, http_version);

    //SSL options
    if (
        getProfileAgentSettingWithDefault<bool>(false, "agent.config.message.ignoreSslValidation") == false
    )
    {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_verify_certificate);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_CTX_DATA, static_cast<void*>(&bearer));
    } else
    {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        dbgWarning(D_HTTP_REQUEST) << "Ignoring SSL validation";
    }

    //Header options
    curl_easy_setopt(curl_handle, CURLOPT_URL, curl_url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writeResponseCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &out_file);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, timeout);
    if (ca_path != "") curl_easy_setopt(curl_handle, CURLOPT_CAINFO, ca_path.c_str());
    headers = curl_slist_append(headers, "Accept: */*");
    string auth = string("Authorization: Bearer ") + bearer;
    headers = curl_slist_append(headers, auth.c_str());
    headers = curl_slist_append(headers, "User-Agent: Infinity Next (a7030abf93a4c13)");
    string uuid_header = string("X-Trace-Id: ") + TraceIdGenerator::generateTraceId();
    headers = curl_slist_append(headers, "Connection: close");
    headers = curl_slist_append(headers, uuid_header.c_str());

    // Proxy options
    if (!proxy.empty())
    {
        curl_easy_setopt(curl_handle, CURLOPT_PROXY, proxy.c_str());
        if (!proxy_credentials.empty())
        {
            proxy_headers = curl_slist_append(proxy_headers, proxy_credentials.c_str());
            //Apply proxy headers
            curl_easy_setopt(curl_handle, CURLOPT_PROXYHEADER, proxy_headers);
        }
        dbgTrace(D_HTTP_REQUEST) << "Using Proxy : " << proxy;
    }

    //Apply headers
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
}

int
HttpsCurl::verify_certificate(int preverify_ok, X509_STORE_CTX *ctx)
{
    switch (X509_STORE_CTX_get_error(ctx))
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            dbgWarning(D_HTTP_REQUEST) << "SSL verification error: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            dbgWarning(D_HTTP_REQUEST) << "SSL verification error: Certificate not yet valid";
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            dbgWarning(D_HTTP_REQUEST) << "Certificate expired";
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            dbgDebug(D_HTTP_REQUEST) << "Self signed certificate in chain";
            if (getConfigurationWithDefault(false, "orchestration", "Self signed certificates acceptable")) {
                preverify_ok = true;
            }
            break;
        default:
            if (!preverify_ok) {
                dbgWarning(D_HTTP_REQUEST)
                    << "Certificate verification error number: "
                    << X509_STORE_CTX_get_error(ctx);
            }
            break;
    }

    return preverify_ok;
}

CURLcode
HttpsCurl::ssl_ctx_verify_certificate(CURL *, void *sslctx, void *opq)
{
    SSL_CTX *ctx = (SSL_CTX *) sslctx;
    string *token_ptr = static_cast<string*>(opq);
    if(!token_ptr)
    {
        dbgWarning(D_HTTP_REQUEST) << "Invalid token (bearer) was received";
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    string token = *token_ptr;

    if (token.empty())
    {
        return CURLE_OK;
    }

    SSL_CTX_set_verify(
        ctx,
        SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER,
        verify_certificate
    );

    return CURLE_OK;
}

string
TraceIdGenerator::generateRandomString(uint length)
{
    string dst(length, 0);
    static thread_local mt19937 range(random_device{}());
    
    auto randchar = [&]() -> char
    {
        static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        static const size_t size = (sizeof(charset) - 1);
        return charset[ range() % size ];
    };
    
    generate_n(dst.begin(), length, randchar);

    return dst;
}

string
TraceIdGenerator::generateTraceId()
{
    string part1 = generateRandomString(8);
    string part2 = generateRandomString(4);
    string part3 = generateRandomString(4);
    string part4 = generateRandomString(4);
    string part5 = generateRandomString(12);
    return string(part1 + "-" + part2 + "-" + part3 + "-" + part4 + "-" + part5);
}
