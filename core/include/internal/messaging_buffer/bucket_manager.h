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

#ifndef __BUCKET_MANAGER_H__
#define __BUCKET_MANAGER_H__

#include <unordered_map>
#include <iterator>
#include <string>

#include "event_queue.h"
#include "instance_awareness.h"
#include "i_time_get.h"
#include "i_encryptor.h"

using bucketName = std::string;

class BucketManager
{
public:
    void init(const std::string &service_name);
    void fini();
    bool doesExist(const bucketName &);
    void push(const bucketName &, std::string &&);
    bool handleNextBucket();
    bool hasValue();
    EventQueue & peek();

    void flush();

private:
    std::string resolveFilesName(const std::string &file_name);

    std::string buffer_directory      = "";
    std::string next_bucket           = "";
    std::string service_name          = "";
    std::string management_file_path  = "";

    uint buffer_max_size = 0; // in MB
    uint max_buffer_files = 0;

    EventQueue iterator;
    std::unordered_map<bucketName, EventQueue> buckets;
    I_InstanceAwareness *instance_awareness = nullptr;
    I_Encryptor *encryptor                  = nullptr;
};

#endif // __BUCKET_MANAGER_H__
