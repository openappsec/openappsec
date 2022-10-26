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

#ifndef __REST_CONN_H__
#define __REST_CONN_H__

#include <string>
#include "i_mainloop.h"
#include "i_rest_invoke.h"

class RestConn
{
public:
    RestConn(int _fd, I_MainLoop *_mainloop, const I_RestInvoke *_invoke);
    ~RestConn();

    void parseConn() const;

private:
    void stop() const;
    std::string readLine() const;
    std::string readSize(int len) const;
    void sendResponse(const std::string &status, const std::string &body) const;

    int fd;
    I_MainLoop *mainloop;
    const I_RestInvoke *invoke;
};

#endif // __REST_CONN_H__
