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

#ifndef __SMART_BIO_H__
#define __SMART_BIO_H__

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/x509v3.h"

namespace smartBIO
{

template<class T> struct Destrctor;

template<>
struct Destrctor<BIO>
{
    void
    operator()(BIO *pointer) const
    {
        if (pointer != nullptr) BIO_free_all(pointer);
    }
};

// LCOV_EXCL_START Reason: No ssl ut
template<>
struct Destrctor<SSL_CTX>
{
    void
    operator()(SSL_CTX *pointer) const
    {
        if (pointer != nullptr) SSL_CTX_free(pointer);
    }
};

template<>
struct Destrctor<X509>
{
    void
    operator()(X509 *pointer) const
    {
        if (pointer != nullptr) X509_free(pointer);
    }
};

template<>
struct Destrctor<EVP_PKEY>
{
    void
    operator()(EVP_PKEY *pointer) const
    {
        if (pointer != nullptr) EVP_PKEY_free(pointer);
    }
};
// LCOV_EXCL_STOP

template<class OpenSSLType>
using BioUniquePtr = std::unique_ptr<OpenSSLType, smartBIO::Destrctor<OpenSSLType>>;

} // namespace SmartBIO

#endif // __SMART_BIO_H__
