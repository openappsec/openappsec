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

#ifndef __MESSAGING_DOWNLOADER_SERVER_H__
#define __MESSAGING_DOWNLOADER_SERVER_H__

#include "i_messaging_downloader.h"
#include "i_messaging.h"
#include "i_rest_api.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "i_agent_details.h"
#include "component.h"

USE_DEBUG_FLAG(D_COMMUNICATION);

class MessagingDownloaderServer
        :
    public Component,
    Singleton::Provide<I_MessagingDownloader>,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_AgentDetails>
{
public:
    MessagingDownloaderServer();
    ~MessagingDownloaderServer();

    void init();
    void fini();

    void preload();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __MESSAGING_DOWNLOADER_SERVER_H__
