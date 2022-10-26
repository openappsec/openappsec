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

#ifndef __ATTACHMENT_REGISTRATOR_H__
#define __ATTACHMENT_REGISTRATOR_H__

#include "singleton.h"
#include "i_mainloop.h"
#include "i_shell_cmd.h"
#include "i_socket_is.h"
#include "attachment_types.h"
#include "component.h"

#define default_keep_alive_path "/etc/cp/attachmentRegistrator/expiration-socket"

class AttachmentRegistrator
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_Socket>
{
public:
    AttachmentRegistrator();
    ~AttachmentRegistrator();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __ATTACHMENT_REGISTRATOR_H__
