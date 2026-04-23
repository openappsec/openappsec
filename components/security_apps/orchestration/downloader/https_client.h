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

#ifndef __HTTPS_CLIENT_H__
#define __HTTPS_CLIENT_H__

#include <string>
#include "maybe_res.h"
#include "url_parser.h"
#include "orchestration_comp.h"

// LCOV_EXCL_START Reason: Depends on real download server.
class HTTPSClient
{
public:
    Maybe<void> getFile(const URLParser &url, const std::string &out_file, bool auth_required);

private:
    std::string loadCAChainDir();
    Maybe<void> getFileSSL(const URLParser &url, const std::string &out_file, const std::string &_token);
    Maybe<void> getFileSSLDirect(const URLParser &url, const std::string &out_file, const std::string &_token);
    Maybe<void> curlGetFileOverSSL(const URLParser &url, const std::string &out_file, const std::string &_token);
};
// LCOV_EXCL_STOP

#endif // __HTTPS_CLIENT_H__
