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

#ifndef __MOCK_MANIFEST_CONTROLLER_H__
#define __MOCK_MANIFEST_CONTROLLER_H__

#include "i_manifest_controller.h"
#include "cptest.h"

class MockManifestController :
    public Singleton::Provide<I_ManifestController>::From<MockProvider<I_ManifestController>>
{
public:
    MOCK_METHOD1(updateManifest, bool(const std::string &));
    MOCK_METHOD0(loadAfterSelfUpdate, bool());
};

#endif // __MOCK_MANIFEST_CONTROLLER_H__
