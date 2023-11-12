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

#pragma once

namespace Waap {

class ResponseInspectReasons {
public:
    ResponseInspectReasons();
    bool shouldInspect() const;
    void setOpenRedirect(bool flag);
    void setErrorDisclosure(bool flag);
    void setRateLimiting(bool flag);
    void setErrorLimiter(bool flag);
    void setCollectResponseForLog(bool flag);
    void setApplyOverride(bool flag);

    bool getApplyOverride(void);
private:
    bool openRedirect;
    bool errorDisclosure;
    bool errorLimiter;
    bool rateLimiting;
    bool collectResponseForLog;
    bool applyOverride;
};

}
