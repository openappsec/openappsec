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

#ifndef __MOCK_MESSAGING_DOWNLOADER_H__
#define __MOCK_MESSAGING_DOWNLOADER_H__

#include "cptest.h"
#include <string>

#include "i_messaging_downloader.h"

class MockMessagingDownloader
        :
    public Singleton::Provide<I_MessagingDownloader>::From<MockProvider<I_MessagingDownloader>>
{
public:
    MOCK_METHOD4(
        downloadFile,
        bool(
            const std::string &,
            const std::string &,
            OnCompleteCB,
            const unsigned int
        )
    );
};


#endif // __MOCK_MESSAGING_DOWNLOADER_H__
