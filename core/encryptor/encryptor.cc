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

#include "encryptor.h"

#include <stdio.h>
#include <vector>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include "cpnano_base64/base64.h"
#include "config.h"
#include "debug.h"

using namespace std;

static const int bits = 256;

class Encryptor::Impl : Singleton::Provide<I_Encryptor>::From<Encryptor>
{
    // Base64
    string base64Encode(const string &input) override;
    string base64Decode(const string &input) override;

    // Obfuscating
    string obfuscateXor(const string &input) override;
    string obfuscateXorBase64(const string &input) override;


private:
};

string
Encryptor::Impl::base64Encode(const string &input)
{
    return Base64::encodeBase64(input);
}

string
Encryptor::Impl::base64Decode(const string &input)
{
    return Base64::decodeBase64(input);
}

string
Encryptor::Impl::obfuscateXor(const string &input)
{
    //Any chars will work
    static const string key = "CHECKPOINT";
    string output;
    for (size_t i = 0; i < input.size(); i++) {
        output.push_back(input[i] ^ key[i % key.size()]);
    }
    return output;
}

string
Encryptor::Impl::obfuscateXorBase64(const string &input)
{
    string obfuscated = obfuscateXor(input);
    return base64Encode(obfuscated);
}


void
Encryptor::preload()
{
    registerExpectedConfiguration<string>("encryptor", "Data files directory");
}

Encryptor::Encryptor() : Component("Encryptor"), pimpl(make_unique<Impl>()) {}
Encryptor::~Encryptor() {}
