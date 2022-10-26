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

class ResponseInjectReasons {
public:
    ResponseInjectReasons();
    void clear();
    bool shouldInject() const;
    void setAntibot(bool flag);
    void setCsrf(bool flag);
    void setSecurityHeaders(bool flag);
    bool shouldInjectAntibot() const;
    bool shouldInjectCsrf() const;
    bool shouldInjectSecurityHeaders() const;
private:
    bool csrf;
    bool antibot;
    bool securityHeaders;
};

}
