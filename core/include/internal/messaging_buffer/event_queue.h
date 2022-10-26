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

#ifndef __EVENT_QUEUE_H__
#define __EVENT_QUEUE_H__

#include <boost/range/iterator_range.hpp>

#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>
#include <list>
#include <chrono>

#include "i_time_get.h"
#include "maybe_res.h"

USE_DEBUG_FLAG(D_EVENT_BUFFER);

class EventQueueFile
{
public:
    EventQueueFile(const std::string &_file_path)
            :
        file_path(_file_path)
    {}

    EventQueueFile(
        const std::string &file_location_path,
        const std::string &file_extention,
        bool is_file_compressed);

    EventQueueFile(const EventQueueFile &other_event, int _num_of_events_in_file, uint64_t _size_of_file)
            :
        file_path(other_event.file_path),
        suffix(other_event.suffix),
        num_of_events_in_file(_num_of_events_in_file),
        size_of_file(_size_of_file)
    {}

    static const std::string zip_file_suffix;
    const std::string & getFilePath() const { return file_path; }
    bool isCompressed() const { return is_compressed; }
    int getSuffix() const { return suffix; }
    int getNumOfEvents() const { return num_of_events_in_file; }
    uint64_t getFileSizeInBytes() const { return size_of_file; }

    void restoreNumberOfLines();
    void incFileSize(uint64_t size_to_add);
    void handleCompression(int size_of_files_list);
    void decompress(const std::string &infilename, const std::string &outfilename, bool remove_old = true);
    void compress();

private:
    std::string file_path;
    int suffix = -1;
    bool is_compressed = false;
    int num_of_events_in_file = 0;
    size_t size_of_file = 0;
};

class EventQueue
{
public:
    EventQueue() = default;
    ~EventQueue();

    void init(const std::string &path, uint max_buff_size);
    void fini();
    bool isEmpty() const;
    const std::string & peek();
    void push(std::string &&event_data);
    void reloadEventsIntoList(const std::string &path);

    Maybe<void> refreshBufferFile();
    void refreshReadBuff();

    void trim();
    void flush();

private:
    void rotate();
    void updateReadFile();
    void setReaderFileAndOpen(const EventQueueFile &file);
    void sortEventFilesBySuffix(std::vector<EventQueueFile> &tmp_vec);
    void pushNewEventQueueFile(EventQueueFile &eventFile, std::vector<EventQueueFile> &tmp_vec);
    double getSizeMB(double size_in_B) const;
    Maybe<void> writeCachesToFile();
    void enforceMaxNumberOfFiles();

    // File management
    std::list<EventQueueFile> files; //front is write, back is read
    std::ifstream reader;
    std::ofstream writer;

    // Read & write management
    double max_size; // in MB
    uint64_t size_on_disk; // in B
    uint64_t write_cache_size; // in B
    uint64_t read_cache_size; // in B
    std::list<std::string> write_cache_buff;
    std::list<std::string> read_cache_buff;

    unsigned int num_of_events_on_disk;
    unsigned int read_events_on_disk;

    // Timing management
    std::chrono::microseconds next_sync_freq_in_sec;
    I_TimeGet *timer = nullptr;
    bool is_pending_rotate = false;
    bool is_pending_write = false;
};

#endif // __EVENT_QUEUE_H__
