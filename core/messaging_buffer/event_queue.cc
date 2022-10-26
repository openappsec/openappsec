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

#include "messaging_buffer/event_queue.h"

#include <string>
#include <cstdio>
#include <stdio.h>
#include <vector>
#include <algorithm>
#include <sys/stat.h>
#include <chrono>
#include <dirent.h>

#include "zlib.h"
#include "config.h"
#include "debug.h"
#include "messaging_buffer.h"
#include "i_mainloop.h"

using namespace std;

USE_DEBUG_FLAG(D_EVENT_BUFFER);

class MessagingBuffer;

const string EventQueueFile::zip_file_suffix = ".cpz";

static const size_t size_of_new_line = strlen("\n");
static const uint MB_in_bytes = 1<<20;

string
parseFilePath(int suffix, string file_path)
{
    return suffix == -1 ? file_path : file_path + string(".") + to_string(suffix);
}

static void
performSafeYield()
{
    auto env = Singleton::Consume<I_Environment>::by<MessagingBuffer>();
    auto can_not_yield = env->get<bool>("Not part of coroutine");
    if (can_not_yield.ok() && *can_not_yield) return;
    Singleton::Consume<I_MainLoop>::by<MessagingBuffer>()->yield();
}

// If the program crashed during rotation, a tmp file was created without removing the old one
// Thus need to remove non tmp file and rename the tmp file
void
restoreTmpFile(const string &file_name)
{
    dbgTrace(D_EVENT_BUFFER) << "Handling a temporary file during init. File: " << file_name;
    string new_file_name = file_name.substr(0, strlen(file_name.c_str()) - strlen(".tmp"));
    remove(new_file_name.c_str());
    if (rename(file_name.c_str(), new_file_name.c_str()) != 0) {
        dbgWarning(D_EVENT_BUFFER)
            << "Couldn't handle a temporary file during init. Couldn't rename: "
            << file_name
            << ", to: "
            << new_file_name
            << ". Errno: "
            << strerror(errno);
    }
}

EventQueue::~EventQueue()
{
    if (reader.is_open()) reader.close();
    if (writer.is_open()) writer.close();
}

void
EventQueue::setReaderFileAndOpen(const EventQueueFile &file)
{
    string file_path = parseFilePath(file.getSuffix(), file.getFilePath());
    reader.open(file_path);
    if (!reader.is_open() && ifstream(file_path).good()) {
        dbgWarning(D_EVENT_BUFFER)
            << "Failed to open the file for read. File name: "
            << file_path
            << ". Errno: "
            << errno
            << ", Errno: "
            << strerror(errno);
        return;
    }
}

void
EventQueue::sortEventFilesBySuffix(std::vector<EventQueueFile> &tmp_vec)
{
    sort(
        tmp_vec.begin(),
        tmp_vec.end(),
        [](const EventQueueFile &first, const EventQueueFile &second)
        {
            return first.getSuffix() < second.getSuffix();
        }
    );
    for (const EventQueueFile &file: tmp_vec) {
        files.emplace_back(file);
    }
    for (auto &file: files) {
        file.restoreNumberOfLines();
        num_of_events_on_disk += file.getNumOfEvents();
        size_on_disk += file.getFileSizeInBytes();
    }
}

void
EventQueue::enforceMaxNumberOfFiles()
{
    uint max_files_to_rotate = getProfileAgentSettingWithDefault<uint>(
        10,
        "eventBuffer.maxNumberOfEventQueueFiles"
    );

    while (files.size() >= max_files_to_rotate) {
        performSafeYield();
        string file_to_delete = files.back().getFilePath() + string(".") + to_string(files.back().getSuffix());
        dbgDebug(D_EVENT_BUFFER)
            << "Event Queue passed the maximum number of files it should contain by "
            << files.size() - max_files_to_rotate
            << " files. Removing the file: "
            << file_to_delete
            << ". This action reduced the number of events on disk by "
            << files.back().getNumOfEvents()
            << " and reduced the events buffers' size of disk by "
            << files.back().getFileSizeInBytes()
            << " bytes.";
        num_of_events_on_disk -= files.back().getNumOfEvents();
        size_on_disk -= files.back().getFileSizeInBytes();
        updateReadFile();
    }
}

// In case the agent crashed or stopped, iterate over all files.
// if files with same path prefix exist, insert them to the list.
void
EventQueue::reloadEventsIntoList(const string &path) {
    dbgFlow(D_EVENT_BUFFER) << "Trying to reload event buffer from persistent location. Path: " << path;
    string dir_path;
    if (path.find("/") != string::npos) {
        dir_path = path.substr(0, path.find_last_of("/"));
    } else {
        dir_path = path;
    }

    dbgDebug(D_EVENT_BUFFER) << "Event queue directory to iterate: " << dir_path;

    struct dirent *entry = nullptr;
    DIR *directory = opendir(dir_path.c_str());

    if (directory == nullptr) {
        int orig_errno = errno;
        dbgWarning(D_EVENT_BUFFER) << "Failed to open directory. Path: " << dir_path << ", Errno: " << orig_errno;
        return;
    }

    vector<EventQueueFile> tmp_vec;
    while ((entry = readdir(directory))) {
        string entry_file_name = entry->d_name;
        static const string curr_dir(".");
        static const string parent_dir("..");
        if (entry_file_name == curr_dir || entry_file_name == parent_dir) {
            dbgTrace(D_EVENT_BUFFER)
                << "Skipping reload of events from irrelevant directory entries. Entry name: "
                << entry_file_name;
            continue;
        }

        bool file_has_extension = entry_file_name.find(".") != string::npos;
        if (!file_has_extension) {
            dbgTrace(D_EVENT_BUFFER)
                << "Skipping reload of events who's entry lack extension. Entry name: "
                << entry_file_name
                << ", Path: "
                << path;
            continue;
        }
        string file_extension = entry_file_name.substr(entry_file_name.find_last_of("."));

        dbgDebug(D_EVENT_BUFFER) << "Event queue file current extension: " << file_extension;

        if (file_extension == ".tmp") {
            restoreTmpFile(entry_file_name);
            continue;
        }

        bool is_compressed = file_extension == EventQueueFile::zip_file_suffix;
        string base_name =
            file_has_extension ?
                entry_file_name.substr(0, entry_file_name.find_last_of(".")) :
                entry_file_name;
        if (is_compressed && base_name.find(".") != string::npos) {
            file_extension = base_name.substr(base_name.find_last_of(".") + 1);
            base_name = base_name.substr(0, base_name.find_last_of("."));
        }

        dbgDebug(D_EVENT_BUFFER)
            << "Trying to load event queue file from directory. File name: "
            << entry_file_name
            << ", does file has extension: "
            << (file_has_extension ? "true" : "false")
            << ", base name: "
            << base_name
            << ", is compressed: "
            << (is_compressed ? "true" : "false");

        if (path.find(base_name) == string::npos) {
            dbgTrace(D_EVENT_BUFFER)
                << "Skipping reload of events from irrelevant directory entries. Entry name: "
                << entry_file_name
                << ", Entry path: "
                << path
                << ", Entry file base name: "
                << base_name;
            continue;
        }

        int max_files_to_rotate = getProfileAgentSettingWithDefault<int>(
            10,
            "eventBuffer.maxNumberOfEventQueueFiles"
        );
        EventQueueFile new_file(path, file_extension, is_compressed);
        if (new_file.getSuffix() < max_files_to_rotate) {
            dbgDebug(D_EVENT_BUFFER)
                << "Reloading file "
                << new_file.getFilePath()
                << " with suffix "
                << new_file.getSuffix();
            tmp_vec.push_back(new_file);
        } else {
            dbgWarning(D_EVENT_BUFFER)
                << "File "
                << new_file.getFilePath()
                << " with suffix "
                << new_file.getSuffix()
                << " will not be reloaded due to limitation of maximum number of event queue files.";
        }
    }
    sortEventFilesBySuffix(tmp_vec);
}

void
EventQueueFile::restoreNumberOfLines()
{
    string tmp_name;
    if (isCompressed()) {
        string compressed_name = getFilePath() + "." + to_string(getSuffix()) + zip_file_suffix;
        tmp_name = getFilePath() + "." + to_string(getSuffix());
        decompress(compressed_name, tmp_name, false);
    }
    string line;
    ifstream reader(parseFilePath(getSuffix(), getFilePath()));
    while (getline(reader, line)) {
        incFileSize(line.size() + size_of_new_line);
    }
    remove(tmp_name.c_str());
}

void
EventQueue::init(const string &path, uint max_buff_size)
{
    dbgTrace(D_EVENT_BUFFER) << "Initializing Event Queue. Path: " << path << ", Max buffer size: " << max_buff_size;
    max_size = max_buff_size;
    files.emplace_front(EventQueueFile(path));
    reloadEventsIntoList(path);
    if (timer == nullptr) timer = Singleton::Consume<I_TimeGet>::by<MessagingBuffer>();;
    dbgAssert(timer != nullptr) << "Failed to find the time component";

    uint next_sync_in_sec_base_settings = getProfileAgentSettingWithDefault<uint>(
        10,
        "eventBuffer.syncToDiskFrequencyInSec"
    );
    next_sync_freq_in_sec =
        timer->getMonotonicTime() +
        chrono::seconds(getConfigurationWithDefault<uint>(
            next_sync_in_sec_base_settings,
            "Event Buffer",
            "sync to disk frequency in sec"
        ));

    setReaderFileAndOpen(files.back());
    reader.seekg(0, ios::beg);
}

// if current reader file is empty, iterate over to the next one
Maybe<void>
EventQueue::refreshBufferFile()
{
    if (read_events_on_disk == 0) {
        dbgDebug(D_EVENT_BUFFER) << "Nothing to refresh: all events on the disk still pending";
        return Maybe<void>();
    }

    if (!reader.is_open()) return genError("nothing to trim since the file is still unopened");

    int num_of_events_to_transfare = 0;
    uint64_t size_of_events_to_transfare = 0;
    string line;
    vector<string> file_content;
    while (getline(reader, line)) {
        performSafeYield();
        file_content.push_back(line);
        num_of_events_to_transfare++;
        size_of_events_to_transfare += (line.size() + size_of_new_line);
    }
    reader.close();

    string read_file = parseFilePath(files.back().getSuffix(), files.back().getFilePath());
    string temp_file = read_file + ".tmp";
    remove(temp_file.c_str());
    writer.open(temp_file, ios_base::app);
    if (!writer.is_open()) {
        dbgWarning(D_EVENT_BUFFER)
            << "Failed to open the file for write (append): "
            << temp_file
            << ". Errno: "
            << errno
            << ", Errno: "
            << strerror(errno);
        for (auto &line : file_content) {
            performSafeYield();
            read_cache_buff.push_back(line);
            read_cache_size += line.size();
        }
        return genError("cannot open new cache file");
    }
    num_of_events_on_disk -= files.back().getNumOfEvents();
    size_on_disk -= files.back().getFileSizeInBytes();
    for (const string &single_event: file_content) {
        performSafeYield();
        writer << single_event << '\n';
        num_of_events_on_disk++;
        size_on_disk += (single_event.size() + size_of_new_line);
    }
    writer.close();
    remove(read_file.c_str());
    rename(temp_file.c_str(), read_file.c_str());

    reader.open(read_file);
    if (!reader.is_open()) return genError("failed to open cache file to skip cached events");
    EventQueueFile updated_file{
        files.back(),
        num_of_events_to_transfare,
        size_of_events_to_transfare
    };
    files.pop_back();
    files.emplace_back(updated_file);
    return Maybe<void>();
}

void
EventQueue::push(string &&event_data)
{
    if (files.front().getFilePath() == "") {
        dbgWarning(D_EVENT_BUFFER) << "Cannot save events to a non-existent file";
        return;
    }
    event_data.erase(remove(event_data.begin(), event_data.end(), '\n'), event_data.end()); // remove all new-line

    write_cache_size += event_data.size();
    write_cache_buff.push_back(move(event_data)); // hold data in RAM in case write will fail

    if (is_pending_rotate) {
        dbgDebug(D_EVENT_BUFFER)
            << "Rotation pending. Accumulating events (write_cache_buff size="
            << write_cache_buff.size()
            << ")";
        return;
    }

    uint cache_buff_max_size_base_settings = getProfileAgentSettingWithDefault<uint>(
        100,
        "eventBuffer.syncToDiskWriteCacheBufferSize"
    );
    uint cache_buff_max_size = getConfigurationWithDefault<uint>(
        cache_buff_max_size_base_settings,
        "Event Buffer",
        "sync to disk write cache buffer size"
    );

    if (timer->getMonotonicTime() < next_sync_freq_in_sec && write_cache_buff.size() < cache_buff_max_size) {
        dbgTrace(D_EVENT_BUFFER)
            << "Not writing event to disk because cache buffer is not full and time is before sync time interval ";
        return;
    }

    uint next_sync_in_sec_base_settings = getProfileAgentSettingWithDefault<uint>(
        10,
        "eventBuffer.syncToDiskFrequencyInSec"
    );
    next_sync_freq_in_sec =
        timer->getMonotonicTime() +
        chrono::seconds(getConfigurationWithDefault<uint>(
            next_sync_in_sec_base_settings,
            "Event Buffer",
            "sync to disk frequency in sec"
        ));

    if (
        files.front().getNumOfEvents() != 0 &&
        getSizeMB(write_cache_size + files.front().getFileSizeInBytes()) >= max_size
    ) {
        dbgTrace(D_EVENT_BUFFER) << "Event buffer queue reached max size, pending files rotation.";
        is_pending_rotate = true;

        Singleton::Consume<I_MainLoop>::by<MessagingBuffer>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [&] ()
            {
                dbgWarning(D_EVENT_BUFFER)
                    << "Failed to buffer a message after reaching the maximum buffer size."
                    << "Compressing the buffer and creating a new one.";
                rotate();

                files.push_front(EventQueueFile(files.front().getFilePath()));
                dbgInfo(D_EVENT_BUFFER) << "Successfully appended new buffer to list";
                is_pending_rotate = false;
            },
            "Event queue rotation",
            false
        );

        return;
    }

    if (is_pending_write) {
        dbgDebug(D_EVENT_BUFFER)
            << "Writing events pending. Accumulating events (write_cache_buff size="
            << write_cache_buff.size()
            << ")";
        return;
    }

    is_pending_write = true;

    Singleton::Consume<I_MainLoop>::by<MessagingBuffer>()->addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        [&] ()
        {
            writer.open(files.front().getFilePath(), ios_base::app);
            if (!writer.is_open()) {
                dbgWarning(D_EVENT_BUFFER)
                    << "Failed to open the file for write (append):"
                    << files.front().getFilePath()
                    << ". Errno: "
                    << errno
                    << ", Errno: "
                    << strerror(errno);
                return;
            }

            for_each(
                write_cache_buff.begin(),
                write_cache_buff.end(),
                [this](string &single_event)
                {
                    size_t event_size = single_event.size();
                    write_cache_size -= event_size;
                    writer << single_event << '\n';
                    num_of_events_on_disk++;
                    files.front().incFileSize(event_size + size_of_new_line);
                    size_on_disk += (event_size + size_of_new_line);
                    performSafeYield();
                }
            );

            write_cache_buff.clear();
            writer.close();
            is_pending_write = false;
        },
        "Event queue rotation",
        false
    );
}

Maybe<void>
EventQueue::writeCachesToFile()
{
    vector<string> file_content(read_cache_buff.begin(), read_cache_buff.end());
    if (num_of_events_on_disk > 0) {
        reader.close();
        reader.open(files.front().getFilePath());
        if (!reader.is_open()) {
            return genError("Failed to open the file for read: " + files.front().getFilePath());
        }
        string line;
        reader.clear();
        while (getline(reader, line)) {
            file_content.push_back(line);
        }
    }
    file_content.insert(file_content.end(), write_cache_buff.begin(), write_cache_buff.end());

    string temp_file_name = files.front().getFilePath() + ".tmp";
    writer.open(temp_file_name, ios_base::app|ios_base::out);

    if (!writer.is_open()) {
        return genError("Failed to open the file for write, file: " + temp_file_name);
    }

    int current_num_of_events = 0;
    uint64_t current_size_of_events = 0;
    for (const string &single_event: file_content) {
        writer << single_event << '\n';
        current_num_of_events++;
        current_size_of_events = (single_event.size() + size_of_new_line);
    }
    writer.close();

    remove(files.front().getFilePath().c_str()); // File possibly can be uncreated by this point
    if (rename(temp_file_name.c_str(), files.front().getFilePath().c_str()) != 0) {
        return genError("Error renaming temp file " + temp_file_name + " to " + files.front().getFilePath());
    }
    EventQueueFile new_file{files.front(), current_num_of_events, current_size_of_events};
    files.pop_front();
    files.emplace_front(new_file);
    return Maybe<void>();
}

bool
EventQueue::isEmpty() const
{
    return num_of_events_on_disk + read_events_on_disk + read_cache_buff.size() +  write_cache_buff.size() == 0;
}

void
EventQueue::fini()
{
    auto write_caches = writeCachesToFile();
    if (!write_caches.ok()) {
        dbgWarning(D_EVENT_BUFFER)
            << "Failed to write cache to file, Error: "
            << write_caches.getErr();
    }
}

const string &
EventQueue::peek()
{
    static const string error_reading = "";
    if (isEmpty()) {
        dbgDebug(D_EVENT_BUFFER)
            << "Number of events on disk: "
            << num_of_events_on_disk
            << endl
            << "Number of read events on disk: "
            << read_events_on_disk
            << endl
            << "Read cache size: "
            << read_cache_buff.size()
            << endl
            << "Write cache size: "
            << write_cache_buff.size();
        dbgWarning(D_EVENT_BUFFER)
            << "Cannot peek at an empty queue. file: "
            << files.back().getFilePath();
        return error_reading;
    }
    if (read_cache_buff.empty()) {
        refreshReadBuff();
        if (read_cache_buff.empty()) {
            dbgDebug(D_EVENT_BUFFER) << "Read cache buffer is empty";
            return error_reading;
        }
    }
    return read_cache_buff.front();
}

void
EventQueue::refreshReadBuff()
{
    if (files.empty()) {
        dbgDebug(D_EVENT_BUFFER) << "Buffer files are empty";
        return;
    }
    if (files.back().getNumOfEvents() == 0) {
        updateReadFile();
        if (files.empty() | (files.back().getNumOfEvents() == 0)) {
            dbgDebug(D_EVENT_BUFFER) << "Buffered events file is empty.";
            read_cache_buff.splice(read_cache_buff.begin(), write_cache_buff);
            read_cache_size += write_cache_size;
            write_cache_size = 0;
            return;
        }
    }
    if (!reader.is_open()) {
        dbgTrace(D_EVENT_BUFFER)
            << "Buffered events file is closed trying to open it. file: "
            << files.back().getFilePath();
        setReaderFileAndOpen(files.back());
    }

    uint cache_buff_max_size_base_settings = getProfileAgentSettingWithDefault<uint>(
        100,
        "eventBuffer.syncToDiskWriteCacheBufferSize"
    );
    uint cache_buff_max_size = getConfigurationWithDefault<uint>(
        cache_buff_max_size_base_settings,
        "Event Buffer",
        "sync to disk write cache buffer size"
    );

    int counter = 0;
    while (read_cache_buff.size() < cache_buff_max_size && counter < files.back().getNumOfEvents()) {
        performSafeYield();
        string line;
        if (!getline(reader, line)) {
            reader.clear();
            break;
        }
        read_events_on_disk ++;
        counter++;
        read_cache_buff.push_back(line);
        read_cache_size += line.size();
    }
    refreshBufferFile();
}

void
EventQueue::updateReadFile()
{
    if (files.back().getSuffix() == -1) {
        return;
    }

    if (!reader.is_open()) {
        dbgTrace(D_EVENT_BUFFER)
            << "Buffered events file is closed trying to open it. file: "
            << files.back().getFilePath();
        setReaderFileAndOpen(files.back());
    }

    string file_to_delete = files.back().getFilePath() + string(".") + to_string(files.back().getSuffix());

    string new_file =
        files.back().getSuffix() == 0 ?
        files.back().getFilePath() :
        files.back().getFilePath() + string(".") + to_string(files.back().getSuffix() - 1);

    dbgDebug(D_EVENT_BUFFER)
        << "Updating the reader file. Current file: "
        << file_to_delete
        << ", New file: "
        << new_file;

    reader.close();
    files.pop_back();
    remove(file_to_delete.c_str());
    if (files.back().isCompressed()) files.back().decompress(new_file + files.back().zip_file_suffix, new_file);
    reader.open(new_file);
    if (!reader.is_open() && ifstream(new_file).good()) {
        dbgWarning(D_EVENT_BUFFER)
            << "Failed to open the file for read: "
            << new_file
            << ". Errno: "
            << errno
            << ", Errno: "
            << strerror(errno);
        return;
    }
}

void
EventQueue::trim()
{
    if (!read_cache_buff.empty()) {
        read_cache_size -= read_cache_buff.front().size();
        read_cache_buff.pop_front();
        dbgTrace(D_EVENT_BUFFER) << "Removed first element in read cache buffer";
        if (!read_cache_buff.empty()) return;
    }

    refreshReadBuff();
}

void
EventQueue::flush()
{
    for (auto &file: files) {
        string file_path = parseFilePath(file.getSuffix(), file.getFilePath());
        remove(file_path.c_str());
    }
    write_cache_buff.clear();
    read_cache_buff.clear();
    size_on_disk = 0;
    num_of_events_on_disk = 0;
    write_cache_size = 0;
    read_cache_size = 0;
    read_events_on_disk = 0;
    reader.close();
    writer.close();
}

double
EventQueue::getSizeMB(double size_in_B) const
{
    return size_in_B/MB_in_bytes;
}

void
EventQueue::rotate()
{
    enforceMaxNumberOfFiles();

    for_each(
        files.rbegin(),
        files.rend(),
        [&](EventQueueFile &file)
    {
        file.handleCompression(files.size());
    });
}

void
EventQueueFile::handleCompression(int list_length)
{
    bool should_rename = true;
    suffix++;
    string old_name = suffix == 0 ? file_path : file_path + string(".") + to_string(suffix - 1);
    string new_name = file_path + string(".") + to_string(suffix);

    auto rename_on_exit = make_scope_exit(
        [&]()
        {
            if (should_rename) rename(old_name.c_str(), new_name.c_str());
            dbgTrace(D_EVENT_BUFFER)
                << "Renamed a file during rotation. Old file name: "
                << old_name
                << ". New file name: "
                << new_name;
        }
    );
    if (suffix != list_length - 1) { // not the read file
        new_name = new_name + zip_file_suffix;
        if (is_compressed) {
            old_name = old_name + zip_file_suffix;
            return;
        }
        compress();
        should_rename = false;
        return;
    }
    if (is_compressed) {
        old_name = old_name + zip_file_suffix;
        decompress(old_name, new_name);
        should_rename = false;
    }
}

void
EventQueueFile::decompress(const string &infilename, const string &outfilename, bool remove_old)
{
    gzFile infile = gzopen(infilename.c_str(), "rb");
    FILE *outfile = fopen(outfilename.c_str(), "wb");
    char buffer[128];
    int num_read = 0;
    while ((num_read = gzread(infile, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, num_read, outfile);
        performSafeYield();
    }
    gzclose(infile);
    fclose(outfile);
    if (remove_old) {
        remove(infilename.c_str());
        is_compressed = false;
    }
}

void
EventQueueFile::compress()
{
    string infilename =
        suffix == 0 ? file_path : file_path + string(".") + to_string(suffix - 1);
    string outfilename = file_path + string(".") + to_string(suffix) + zip_file_suffix;
    FILE *infile = fopen(infilename.c_str(), "rb");
    gzFile outfile = gzopen(outfilename.c_str(), "wb");
    char inbuffer[128];
    int num_read = 0;
    unsigned long total_read = 0;
    while ((num_read = fread(inbuffer, 1, sizeof(inbuffer), infile)) > 0) {
        total_read += num_read;
        gzwrite(outfile, inbuffer, num_read);
        performSafeYield();
    }
    fclose(infile);
    gzclose(outfile);
    dbgTrace(D_EVENT_BUFFER)
        << "After file compression: Read "
        << total_read
        << "bytes, Wrote "
        << getFileSizeInBytes()
        << "bytes, Compression factor "
        <<  ((1.0-getFileSizeInBytes()*1.0/total_read)*100.0);
    remove(infilename.c_str());
    is_compressed = true;
}

void
EventQueueFile::incFileSize(uint64_t size_to_add)
{
    size_of_file += size_to_add;
    num_of_events_in_file++;
}

EventQueueFile::EventQueueFile(
    const string &file_location_path,
    const string &file_extension_raw,
    bool is_file_compressed)
{
    dbgInfo(D_EVENT_BUFFER)
        << "Creating new event queue file. File's location path: "
        << file_location_path
        << ", File extension: "
        << file_extension_raw
        << "Is Compressed: "
        << (is_file_compressed ? "true" : "false");

    file_path = file_location_path;
    is_compressed = is_file_compressed;
    string file_extension = file_extension_raw;
    try {
        if (!file_extension.empty() && file_extension.front() == '.') {
            file_extension.erase(0, 1); // delete the '.' before the suffix
        }
        suffix = stoi(file_extension);
    } catch (const exception &e) {
        dbgWarning(D_EVENT_BUFFER)
            << "Error reloading event files. File: "
            << file_path
            << ", Error: "
            << e.what();
    }
}
