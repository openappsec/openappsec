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

#ifndef __MOCK_DOWNLOADER_H__
#define __MOCK_DOWNLOADER_H__

#include "cptest.h"
#include "i_downloader.h"

#include <string>

class MockDownloader :
    public Singleton::Provide<I_Downloader>::From<MockProvider<I_Downloader>>
{
public:
    MOCK_CONST_METHOD3(
        downloadFileFromFog,
        Maybe<std::string>(const std::string &, Package::ChecksumTypes, const GetResourceFile &)
    );

    MOCK_CONST_METHOD2(
        downloadVirtualFileFromFog,
        Maybe<std::map<std::pair<std::string, std::string>, std::string>>(
            const GetResourceFile &,
            Package::ChecksumTypes
        )
    );

    MOCK_CONST_METHOD4(
        downloadFileFromURL,
        Maybe<std::string>(const std::string &, const std::string &, Package::ChecksumTypes, const std::string &)
    );

    MOCK_CONST_METHOD1(
        getProfileFromMap,
        std::string(const std::string &)
    );

};

#endif // __MOCK_DOWNLOADER_H__
