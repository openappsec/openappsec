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

#include "messaging_buffer.h"

#include <string>
#include <unordered_map>
#include <sstream>
#include <chrono>
#include <sys/stat.h>
#include "cereal/archives/json.hpp"

#include "messaging_buffer/event_queue.h"
#include "messaging_buffer/bucket_manager.h"
#include "maybe_res.h"
#include "config.h"
#include "debug.h"

USE_DEBUG_FLAG(D_EVENT_BUFFER);

using namespace std;

class MessagingBuffer::Impl
        :
    Singleton::Provide<I_MessagingBuffer>::From<MessagingBuffer>
{
public:
    void init();
    void fini();
    Maybe<HTTPRequestEvent> peekRequest() override;
    void popRequest() override;
    void bufferNewRequest(const HTTPRequestEvent &request, bool is_rejected) override;
    bool isPending(const HTTPRequestSignature &request) override;
    void cleanBuffer() override;
private:
    void loadConfig();
    void initComponents();
    void initRejectedQueue(const string &process_path);

    Maybe<string> deserialize(const HTTPRequestEvent &req);
    Maybe<HTTPRequestEvent> serialize(const string &data);

    string buffer_directory                 = "";
    string log_files_prefix                 = "";
    I_TimeGet *timer                        = nullptr;
    I_Encryptor *encryptor                  = nullptr;
    I_InstanceAwareness *instance_awareness = nullptr;
    BucketManager bucket_manager;
    EventQueue rejected_events;
};

void
MessagingBuffer::Impl::init()
{
    ScopedContext ctx;
    ctx.registerValue<bool>("Not part of coroutine", true);
    
    log_files_prefix = getLogFilesPathConfig();
    dbgTrace(D_EVENT_BUFFER) << "Messaging buffer init, log files prefix: " << log_files_prefix;
    I_Environment *env = Singleton::Consume<I_Environment>::by<MessagingBuffer>();
    string process_path = env->get<string>("Executable Name").unpack();
    string service_name = process_path.substr(process_path.find_last_of("/") + 1);
    loadConfig();
    initComponents();
    mkdir(buffer_directory.c_str(), 0644);
    bucket_manager.init(service_name);
    initRejectedQueue(service_name);
}

void
MessagingBuffer::Impl::fini()
{
    ScopedContext ctx;
    ctx.registerValue<bool>("Not part of coroutine", true);

    bucket_manager.fini();
}

Maybe<HTTPRequestEvent>
MessagingBuffer::Impl::peekRequest()
{
    if (!bucket_manager.hasValue()) {
        dbgDebug(D_EVENT_BUFFER) << "No data avaliable";
        return genError("No data avaliable");
    }
    EventQueue &tmp = bucket_manager.peek();
    if (tmp.isEmpty()) {
        dbgDebug(D_EVENT_BUFFER) << "Next bucket returned empty queue";
        return genError("No data available in empty bucket");
    }
    auto request = tmp.peek();
    if (request.empty()) {
        popRequest();
        return genError("Request is empty, message is popped");
    }
    return serialize(encryptor->base64Decode(request));
}

void
MessagingBuffer::Impl::popRequest()
{
    bucket_manager.handleNextBucket();
}

void
MessagingBuffer::Impl::bufferNewRequest(const HTTPRequestEvent &request, bool is_rejected)
{
    auto raw_data = deserialize(request);
    if (!raw_data.ok()) {
        string dbg_msg =
            "Cannot buffer the request. Error: " +
            raw_data.getErr() +
            ". Request: "
            + request.getSignature();

        dbgWarning(D_EVENT_BUFFER) << dbg_msg;
        dbgDebug(D_EVENT_BUFFER)
            << dbg_msg
            << ", headers: "
            << request.getHeaders()
            << ", body: "
            << request.getBody();
        return;
    }

    if (is_rejected) {
        rejected_events.push(raw_data.unpackMove());
        return;
    }

    string req_bucket_name = request.getSignature();
    bucket_manager.push(req_bucket_name, raw_data.unpackMove());
}

bool
MessagingBuffer::Impl::isPending(const HTTPRequestSignature &request)
{
    string req_bucket_name = request.getSignature();
    return bucket_manager.doesExist(req_bucket_name);
}

void
MessagingBuffer::Impl::cleanBuffer()
{
    bucket_manager.flush();
    rejected_events.flush();
}

void
MessagingBuffer::Impl::initComponents()
{
    encryptor = Singleton::Consume<I_Encryptor>::by<MessagingBuffer>();
    instance_awareness = Singleton::Consume<I_InstanceAwareness>::by<MessagingBuffer>();
}

void
MessagingBuffer::Impl::loadConfig()
{
    string base_folder_setting = getProfileAgentSettingWithDefault<string>(
        log_files_prefix + "/nano_agent/event_buffer",
        "eventBuffer.baseFolder"
    );
    buffer_directory = getConfigurationWithDefault<string>(
        base_folder_setting,
        "Event Buffer",
        "base folder"
    );
}

void
MessagingBuffer::Impl::initRejectedQueue(const string &service_name)
{
    string buffer_dir_base_folder_setting = getProfileAgentSettingWithDefault<string>(
        log_files_prefix + "/nano_agent/event_buffer",
        "eventBuffer.baseFolder"
    );
    string buffer_directory = getConfigurationWithDefault<string>(
        buffer_dir_base_folder_setting,
        "Event Buffer",
        "base folder"
    );

    uint buffer_max_size_base_settings = getProfileAgentSettingWithDefault<uint>(
        1000,
        "eventBuffer.maxBufferSizeInMB"
    );
    uint buffer_max_size = getConfigurationWithDefault<uint>(
        buffer_max_size_base_settings,
        "Event Buffer",
        "max buffer size in MB"
    );

    uint max_buffer_files_base_settings = getProfileAgentSettingWithDefault<uint>(
        10,
        "eventBuffer.maxBufferFiles"
    );
    uint max_buffer_files = getConfigurationWithDefault<uint>(
        max_buffer_files_base_settings,
        "Event Buffer",
        "max buffer files"
    );

    string service_file_name = instance_awareness->getUniqueID("") + service_name;
    rejected_events.init(
        buffer_directory + "/rejected_events" + service_file_name, buffer_max_size/max_buffer_files
    );
}

Maybe<string>
MessagingBuffer::Impl::deserialize(const HTTPRequestEvent &req)
{
    try {
        stringstream out;
        {
            cereal::JSONOutputArchive out_ar(out);
            req.save(out_ar);
        }
        return out.str();
    } catch (cereal::Exception &e) {
        return genError(e.what());
    }
}

Maybe<HTTPRequestEvent>
MessagingBuffer::Impl::serialize(const string &data)
{
    try {
        HTTPRequestEvent req;
        stringstream in;
        in.str(data);
        try {
            cereal::JSONInputArchive in_ar(in);
            req.load(in_ar);
        } catch (cereal::Exception &e) {
            return genError("JSON parsing failed: " + string(e.what()));
        }
        return req;
    } catch (exception &e) {
        return genError(e.what());
    }
}

MessagingBuffer::MessagingBuffer()
        :
    Component("MessagingBuffer"),
    pimpl(make_unique<Impl>())
{
}

void MessagingBuffer::init() { pimpl->init(); }

void MessagingBuffer::fini() { pimpl->fini(); }

MessagingBuffer::~MessagingBuffer() {}

void
MessagingBuffer::preload()
{
    registerExpectedConfiguration<string>("Event Buffer", "base folder");
    registerExpectedConfiguration<string>("Event Buffer", "base file name");
    registerExpectedConfiguration<uint>("Event Buffer", "max buffer size in MB");
    registerExpectedConfiguration<uint>("Event Buffer", "max buffer files");
    registerExpectedConfiguration<uint>("Event Buffer", "sync to disk frequency in sec");
    registerExpectedConfiguration<uint>("Event Buffer", "send event retry in sec");
}
