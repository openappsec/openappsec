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

#include "messaging_buffer/bucket_manager.h"

#include "messaging_buffer.h"
#include "debug.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_EVENT_BUFFER);

void
BucketManager::init(const string &_service_name)
{
    dbgTrace(D_EVENT_BUFFER) << "Initializing Bucket Manager: Service name: " << _service_name;
    encryptor = Singleton::Consume<I_Encryptor>::by<MessagingBuffer>();
    instance_awareness = Singleton::Consume<I_InstanceAwareness>::by<MessagingBuffer>();
    string log_files_prefix = getLogFilesPathConfig();

    string buffer_dir_base_folder_setting = getProfileAgentSettingWithDefault<string>(
        log_files_prefix + "/nano_agent/event_buffer",
        "eventBuffer.baseFolder"
    );
    dbgTrace(D_EVENT_BUFFER) << "buffer dir base folder setting path: " << buffer_dir_base_folder_setting;
    buffer_directory = getConfigurationWithDefault<string>(
        buffer_dir_base_folder_setting,
        "Event Buffer",
        "base folder"
    );

    uint buffer_max_size_base_settings = getProfileAgentSettingWithDefault<uint>(
        1000,
        "eventBuffer.maxBufferSizeInMB"
    );
    buffer_max_size = getConfigurationWithDefault<uint>(
        buffer_max_size_base_settings,
        "Event Buffer",
        "max buffer size in MB"
    );

    uint max_buffer_files_base_settings = getProfileAgentSettingWithDefault<uint>(10, "eventBuffer.maxBufferFiles");
    max_buffer_files = getConfigurationWithDefault<uint>(
        max_buffer_files_base_settings,
        "Event Buffer",
        "max buffer files"
    );

    service_name = _service_name;
    management_file_path = resolveFilesName(buffer_directory + "/manager");
    iterator.init(management_file_path, buffer_max_size/max_buffer_files);
}

void
BucketManager::fini()
{
    dbgTrace(D_EVENT_BUFFER) << "Finalizing Bucket Manager";
    iterator.fini();
    for (auto &bucket : buckets) {
        bucket.second.fini();
    }
}

bool
BucketManager::doesExist(const bucketName &name)
{
    dbgTrace(D_EVENT_BUFFER) << "Checking if bucket exists and containing data: Bucket name: " << name;
    string base64_name = encryptor->base64Encode(name);

    if (buckets.find(base64_name) == buckets.end()) {
        string management_file = resolveFilesName(buffer_directory + "/" + base64_name);
        buckets.emplace(
            piecewise_construct,
            forward_as_tuple(base64_name),
            forward_as_tuple()
        );
        buckets[base64_name].init(management_file, buffer_max_size/max_buffer_files);
    }

    return !buckets[base64_name].isEmpty();
}

void
BucketManager::push(const bucketName &name, string &&data)
{
    dbgTrace(D_EVENT_BUFFER) << "Pushing data into bucket: Bucket name: " << name;
    string base64_name = encryptor->base64Encode(name);
    if (buckets.find(base64_name) == buckets.end()) {
        dbgTrace(D_EVENT_BUFFER) << "Bucket does not exist, creating new. Bucket name: " << name;
        string management_file = resolveFilesName(buffer_directory + "/" + base64_name);
        buckets.emplace(
            piecewise_construct,
            forward_as_tuple(base64_name),
            forward_as_tuple()
        );
        buckets[base64_name].init(management_file, buffer_max_size/max_buffer_files);
    }

    string copy_name = base64_name;
    string copy_data = encryptor->base64Encode(data);
    buckets[base64_name].push(move(copy_data));
    iterator.push(move(copy_name));
    if (next_bucket.empty()) {
        next_bucket = base64_name;
    }
}

bool
BucketManager::handleNextBucket()
{
    if (!next_bucket.empty()) {
        const string &iterator_peek = iterator.peek();
        if (next_bucket != iterator_peek) {
            dbgWarning(D_EVENT_BUFFER)
                << "Invalid Iteration value, current iteration value does not equal to next bucket"
                << endl
                << "Current iteration value:"
                << iterator_peek
                << endl
                << "Next bucket value:"
                << next_bucket;
        }

        if (!iterator_peek.empty()) {
            iterator.trim();
        }

        buckets[next_bucket].trim();
    }

    if (iterator.isEmpty()) {
        next_bucket.clear();
        dbgTrace(D_EVENT_BUFFER) << "Iteration bucket is empty";
        return false;
    }

    const string &next_req_bucket = iterator.peek();
    if (next_req_bucket.empty()) {
        dbgDebug(D_EVENT_BUFFER)
            << "Next request within iteration bucket is empty, removing sent messages from file:"
            << management_file_path;
        iterator.refreshBufferFile();
        next_bucket.clear();
        return false;
    }
    dbgDebug(D_EVENT_BUFFER)
        << "Next request within iteration bucket is :"
        << next_req_bucket;

    string bucket_path = resolveFilesName(buffer_directory + "/" + next_req_bucket);
    auto bucket = buckets.find(next_req_bucket);
    if (bucket == buckets.end()) {
        dbgDebug(D_EVENT_BUFFER)
            << "Next request bucket was not found within the manager. trying to load it, bucket: "
            << next_req_bucket;
        buckets.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(next_req_bucket),
            std::forward_as_tuple()
        );
        buckets[next_req_bucket].init(bucket_path, buffer_max_size/max_buffer_files);
    }
    next_bucket = next_req_bucket;

    return true;
}

bool
BucketManager::hasValue()
{
    if (iterator.isEmpty()) {
        dbgDebug(D_EVENT_BUFFER) << "Iterator is empty";
        return false;
    }
    if (next_bucket.empty()) {
        dbgDebug(D_EVENT_BUFFER) << "Next bucket is empty";
        return handleNextBucket();
    }

    return true;
}

EventQueue &
BucketManager::peek()
{
    dbgAssert(!next_bucket.empty()) << "Invalid call, handleNextBucket must be called before";
    return buckets[next_bucket];
}

void
BucketManager::flush()
{
    dbgTrace(D_EVENT_BUFFER) << "Flushing all data from the Bucket Manager";
    iterator.flush();
    for (auto &bucket : buckets) {
        bucket.second.flush();
    }
}

string
BucketManager::resolveFilesName(const string &file_name)
{
    string new_name = file_name;
    if (instance_awareness != nullptr)  new_name = new_name + instance_awareness->getUniqueID("");
    return new_name + service_name;
}
