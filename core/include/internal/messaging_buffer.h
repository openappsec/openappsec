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

#ifndef __MESSAGING_BUFFER_H__
#define __MESSAGING_BUFFER_H__

#include <memory>

#include "i_messaging_buffer.h"
#include "i_time_get.h"
#include "i_instance_awareness.h"
#include "singleton.h"
#include "i_encryptor.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "component.h"

class MessagingBuffer
        :
    public Component,
    Singleton::Provide<I_MessagingBuffer>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_MainLoop>
{
public:
    MessagingBuffer();
    ~MessagingBuffer();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __MESSAGING_BUFFER_H__
