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

#ifndef __I_ENCRYPTOR_H__
#define __I_ENCRYPTOR_H__

#include "maybe_res.h"

#include <string>

static const std::string data1_file_name          = "data1.a";
static const std::string data4_file_name          = "data4.a";
static const std::string data6_file_name          = "data6.a";

static const std::string user_cred_file_name      = "data5.a";
static const std::string proxy_auth_file_name     = "data2.a";
static const std::string session_token_file_name  = "data3.a";

class I_Encryptor
{
public:
    // Base64
    virtual std::string base64Encode(const std::string &input) = 0;
    virtual std::string base64Decode(const std::string &input) = 0;

    // Obfuscating
    virtual std::string obfuscateXor(const std::string &input)          = 0;
    virtual std::string obfuscateXorBase64(const std::string &input)    = 0;


protected:
    virtual ~I_Encryptor() {}
};

#endif // __I_ENCRYPTOR_H__
