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

#ifndef __I_MESSAGING_DOWNLOADER_H__
#define __I_MESSAGING_DOWNLOADER_H__

#include <string>
#include <functional>

#include "maybe_res.h"

class I_MessagingDownloader
{
public:
    using OnCompleteCB = std::function<void(const Maybe<std::string> &)>;

    virtual bool downloadFile(
        const std::string &file_name,
        const std::string &url,
        OnCompleteCB cb = nullptr,
        const unsigned int port = 0
    ) = 0;

protected:
    virtual ~I_MessagingDownloader() {}
};

#endif // __I_MESSAGING_DOWNLOADER_H__
