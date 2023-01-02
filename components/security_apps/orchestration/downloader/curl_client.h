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

#include <curl/curl.h>

#if defined(alpine)
#include <openssl/ossl_typ.h>
#else
#include <openssl/types.h>
#endif //ifdef alpine

#include <string>
#include <memory>
#include <fstream>
#include <iostream>
#include <ostream>

#include "i_encryptor.h"
#include "scope_exit.h"
#include "url_parser.h"

USE_DEBUG_FLAG(D_HTTP_REQUEST);

// LCOV_EXCL_START Reason: Depends on real download server.

enum class HTTP_VERSION
{
    HTTP_VERSION_NONE = CURL_HTTP_VERSION_NONE, //libcurl will use whatever it thinks fit.
    HTTP_VERSION_1_0 = CURL_HTTP_VERSION_1_0,
    HTTP_VERSION_1_1 = CURL_HTTP_VERSION_1_1,
    HTTP_VERSION_2_0 = CURL_HTTP_VERSION_2_0
};

class TraceIdGenerator
{
public:
    static std::string generateTraceId();
private:
    static std::string generateRandomString(uint length);
};

class HttpCurl : public Singleton::Consume<I_Encryptor>
{
public:
    HttpCurl(
        const URLParser &_url,
        std::ofstream &_out_file,
        const std::string &_bearer,
        const Maybe<std::string> &proxy_url,
        const Maybe<uint16_t> &proxy_port,
        const Maybe<std::string> &proxy_auth);

    HttpCurl(const HttpCurl &other);

    virtual void setCurlOpts(long timeout = 60L, HTTP_VERSION http_version = HTTP_VERSION::HTTP_VERSION_1_1);
    virtual bool connect();

protected:
    static int trace_http_request(
        CURL *handle,
        curl_infotype type,
        char *data,
        size_t size,
        void *userptr);
    static u_int writeResponseCallback(
        const char *in_buf,
        uint num_of_messages,
        uint size_of_data,
        std::ostream out_stream);
    void print_response_header(std::stringstream &stream);

    const URLParser& url;
    std::ofstream &out_file;
    std::string bearer;
    std::string proxy;
    std::string proxy_credentials;
    std::unique_ptr<CURL, std::function<void(CURL *)>> curl;
    std::string curl_url;
};

class HttpsCurl : public HttpCurl
{
public:
    HttpsCurl(
        const URLParser &_url,
        std::ofstream &_out_file,
        const std::string &_bearer,
        const Maybe<std::string> &proxy_url,
        const Maybe<uint16_t> &proxy_port,
        const Maybe<std::string> &proxy_auth,
        const std::string &_ca_path);

    HttpsCurl(const HttpsCurl& other);

    static CURLcode ssl_ctx_verify_certificate(CURL *curl, void *ssl_ctx, void *opq);
    static int verify_certificate(int preverify_ok, X509_STORE_CTX *ctx);
    void setCurlOpts(long timeout = 60L, HTTP_VERSION http_version = HTTP_VERSION::HTTP_VERSION_1_1) override;

private:
    std::string ca_path;
};
