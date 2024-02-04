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
#include "messaging.h"
#include "http_request_event.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <string>
#include <vector>

#include "config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_MESSAGING_BUFFER);

#ifndef smb
static constexpr uint buffer_max_size_MB = 100;
#else
static constexpr uint buffer_max_size_MB = 3;
#endif

static bool
checkExistence(const string &path)
{
    try {
        struct stat info;
        if (stat(path.c_str(), &info) != 0) return false;
        return info.st_mode & S_IFREG;
    } catch (exception &e) {
        return false;
    }
}

class MessagingBufferComponent::Impl : Singleton::Provide<I_MessageBuffer>::From<MessagingBufferComponent>
{
public:
    void init();

    void pushNewBufferedMessage(
        const string &body,
        HTTPMethod method,
        const string &uri,
        MessageCategory category,
        MessageMetadata message_metadata,
        bool force_immediate_writing
    ) override;

    Maybe<BufferedMessage> peekMessage() override;

    void popMessage() override;

    void cleanBuffer() override;

private:
    void handleBufferedMessages();
    bool sendMessage();
    HTTPStatusCode sendMessage(const BufferedMessage &message) const;

    void handleInMemoryMessages();

    void writeToDisk(const BufferedMessage &message);

    static Maybe<uint32_t> seekStartOfMessage(FILE *file);
    static bool readBytes(FILE *file, uint size_to_read, char *output_bytes);

    bool canWriteToDisk(size_t message_size) const;
    Maybe<uint> getDirectorySize() const;

    // LCOV_EXCL_START - Converting old formats to new format will be added later
    static Maybe<HTTPMethod> convertStringToHTTPMethod(const string &method_string);
    void removeLegacyBuffer(const string &root_path, const string &exec_name);
    void convertLegacyBuffer(const string &body_file_path);
    Maybe<HTTPRequestEvent> serializeOldData(const string &data);
    // LCOV_EXCL_STOP

    vector<BufferedMessage> memory_messages;
    string buffer_input;
    string buffer_output;
    string buffer_root_path;
    uint max_size_on_disk_MB = 0;
    uint curr_no_retries = 0;
    I_ShellCmd *shell_cmd = nullptr;
    I_Encryptor *encryptor = nullptr;
    I_MainLoop *mainloop = nullptr;
    I_Messaging *messaging = nullptr;
};

void
MessagingBufferComponent::Impl::init()
{
    max_size_on_disk_MB = getProfileAgentSettingWithDefault<uint>(buffer_max_size_MB, "eventBuffer.maxSizeOnDiskInMB");
    shell_cmd = Singleton::Consume<I_ShellCmd>::by<Messaging>();
    encryptor = Singleton::Consume<I_Encryptor>::by<Messaging>();
    mainloop = Singleton::Consume<I_MainLoop>::by<Messaging>();
    messaging = Singleton::Consume<I_Messaging>::from<Messaging>();
    
    auto sub_path = getProfileAgentSettingWithDefault<string>("nano_agent/event_buffer/", "eventBuffer.baseFolder");
    buffer_root_path = getLogFilesPathConfig() + "/" + sub_path;
    string full_executable_name =
        Singleton::Consume<I_Environment>::by<Messaging>()->get<string>("Executable Name").unpack();
    string executable_name = full_executable_name.substr(full_executable_name.find_last_of("/") + 1);
    removeLegacyBuffer(buffer_root_path, executable_name);
    mkdir(buffer_root_path.c_str(), 0644);

    auto *instance_awareness = Singleton::Consume<I_InstanceAwareness>::by<Messaging>();
    string unique_id = instance_awareness->getInstanceID().ok() ? instance_awareness->getInstanceID().unpack() : "";
    buffer_input = buffer_root_path + "/" + executable_name + unique_id + ".input";
    buffer_output = buffer_root_path + "/" + executable_name + unique_id + ".output";
    memory_messages.reserve(32);

    uint tmo = getConfigurationWithDefault<uint>(5, "message", "Send event retry in sec");
    mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        chrono::seconds(tmo),
        [this] () { handleBufferedMessages(); },
        "A-sync messaging routine",
        false
    );
    mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        chrono::seconds(2),
        [this] () { handleInMemoryMessages(); },
        "Handling in-memory messages",
        false
    );
}

void
MessagingBufferComponent::Impl::pushNewBufferedMessage(
    const string &body,
    HTTPMethod method,
    const string &uri,
    MessageCategory category,
    MessageMetadata message_metadata,
    bool force_immediate_writing
)
{
    dbgTrace(D_MESSAGING_BUFFER) << "Pushing new message to buffer";

    message_metadata.setShouldBufferMessage(false);

    if (!force_immediate_writing) {
        dbgDebug(D_MESSAGING_BUFFER) << "Holding message temporarily in memory";
        memory_messages.emplace_back(body, method, uri, category, message_metadata);
        return;
    }

    BufferedMessage buffered_message(body, method, uri, category, message_metadata);
    writeToDisk(buffered_message);
}

Maybe<BufferedMessage>
MessagingBufferComponent::Impl::peekMessage()
{
    auto move_cmd =
        "if [ -s " + buffer_input + " ] && [ ! -s " + buffer_output + " ];"
        "then mv " + buffer_input + " " + buffer_output + ";"
        "fi";

    shell_cmd->getExecOutput(move_cmd);

    if (!checkExistence(buffer_output)) return genError(buffer_output + " does not exist");

    FILE *file = fopen(buffer_output.c_str(), "rb");
    if (file == nullptr) {
        dbgWarning(D_MESSAGING_BUFFER) << "Failed to open file for reading. File: " << buffer_output;
        cleanBuffer();
        return genError("Failed to open file");
    }

    auto possition = seekStartOfMessage(file);
    if (!possition.ok()) {
        fclose(file);
        dbgDebug(D_MESSAGING_BUFFER) << "Failed to find message start: " << possition.getErr();
        cleanBuffer();
        return possition.passErr();
    }

    string buffer;
    buffer.resize(*possition);
    auto read = readBytes(file, *possition, const_cast<char *>(buffer.data()));
    fclose(file);
    if (!read) {
        cleanBuffer();
        return genError("Filed to read the message");
    }

    BufferedMessage message;
    try {
        stringstream ss(buffer);
        cereal::JSONInputArchive ar(ss);
        message.load(ar);
    } catch (const cereal::Exception &e) {
        string err = e.what();
        dbgError(D_MESSAGING_BUFFER) << "Parsing backlog error: " << err;
        cleanBuffer();
        return genError("Filed to parse the message: " + err);
    }

    return message;
}

void
MessagingBufferComponent::Impl::popMessage()
{
    dbgTrace(D_MESSAGING_BUFFER) << "Popping message from buffer";

    FILE *file = fopen(buffer_output.c_str(), "rb");
    if (file == nullptr) {
        dbgWarning(D_MESSAGING_BUFFER) << "Failed to open file for reading. File: " << buffer_input;
        return;
    }

    auto possition = seekStartOfMessage(file);
    auto new_size = ftell(file);
    fclose(file);
    if (!possition.ok()) {
        dbgDebug(D_MESSAGING_BUFFER) << "Failed to find message start: " << possition.getErr();
        return;
    }

    int result = truncate(buffer_output.c_str(), new_size);
    if (result == 0) {
        dbgTrace(D_MESSAGING_BUFFER) << "File truncated successfully.";
    } else {
        dbgTrace(D_MESSAGING_BUFFER) << "Error truncating the file: " << strerror(errno);
    }
}

void
MessagingBufferComponent::Impl::cleanBuffer()
{
    dbgTrace(D_MESSAGING_BUFFER) << "Cleaning buffer";
    remove(buffer_input.c_str());
    remove(buffer_output.c_str());
}

void
MessagingBufferComponent::Impl::handleBufferedMessages()
{
    while (true) {
        if (!sendMessage()) return;
        mainloop->yield();
    }
}

bool
MessagingBufferComponent::Impl::sendMessage()
{
    const Maybe<BufferedMessage> &maybe_msg_to_send = peekMessage();
    if (!maybe_msg_to_send.ok()) {
        dbgDebug(D_MESSAGING) << "Peeking failed: " << maybe_msg_to_send.getErr();
        return false;
    }

    auto res = sendMessage(*maybe_msg_to_send);

    if (res == HTTPStatusCode::HTTP_OK) {
        dbgDebug(D_MESSAGING) << "Successfully sent buffered message";
        popMessage();
        curr_no_retries = 0;
        return true;
    }

    if (res == HTTPStatusCode::HTTP_SUSPEND) {
        dbgDebug(D_MESSAGING) << "Suspended connection - sleeping for a while";
        mainloop->yield(chrono::seconds(1));
        return true;
    }

    ++curr_no_retries;
    if (curr_no_retries >= getProfileAgentSettingWithDefault<uint>(10, "eventBuffer.maxNumOfSendigRetries")) {
        dbgWarning(D_MESSAGING) << "Reached maximum number of retries - poping message";
        popMessage();
        curr_no_retries = 0;
    }
    return true;
}

HTTPStatusCode
MessagingBufferComponent::Impl::sendMessage(const BufferedMessage &message) const
{
    auto res = messaging->sendSyncMessage(
        message.getMethod(),
        message.getURI(),
        message.getBody(),
        message.getCategory(),
        message.getMessageMetadata()
    );

    if (res.ok()) return HTTPStatusCode::HTTP_OK;
    if (res.getErr().getHTTPStatusCode() == HTTPStatusCode::HTTP_SUSPEND) return HTTPStatusCode::HTTP_SUSPEND;
    return HTTPStatusCode::HTTP_UNKNOWN;
}

void
MessagingBufferComponent::Impl::handleInMemoryMessages()
{
    auto messages = move(memory_messages);
    memory_messages.reserve(32);

    for (const auto &message : messages) {
        if (sendMessage(message) != HTTPStatusCode::HTTP_OK) writeToDisk(message);
        mainloop->yield();
    }
}

void
MessagingBufferComponent::Impl::writeToDisk(const BufferedMessage &message)
{
    auto serialized_message = message.toString();

    if (!canWriteToDisk(serialized_message.size())) {
        dbgWarning(D_MESSAGING_BUFFER) << "Buffer is full. Message will not be written to disk: " << message.getURI();
        return;
    }

    ofstream file(buffer_input, ios::app);
    if (!file.is_open()) {
        dbgWarning(D_MESSAGING_BUFFER) << "Failed to open file for writing. File: " << buffer_input;
        return;
    }

    uint32_t size = serialized_message.size();
    file.write(serialized_message.data(), size);
    file.write(reinterpret_cast<char *>(&size), sizeof(size));
    char type = 0;
    file.write(&type, 1);
}

Maybe<uint32_t>
MessagingBufferComponent::Impl::seekStartOfMessage(FILE *file)
{
    int type_size = sizeof(char);
    int lenght_size = sizeof(uint32_t);

    if (fseek(file, -type_size, SEEK_END) != 0) return genError("Failed to get to type byte");
    char type;
    if (!readBytes(file, type_size, &type)) return genError("Failed to read type");
    if (type != 0) return genError("Only type 0 is currently supported");

    if (fseek(file, -(type_size + lenght_size), SEEK_END) != 0) return genError("Failed to get to length bytes");
    uint32_t length;
    if (!readBytes(file, lenght_size, reinterpret_cast<char *>(&length))) return genError("Failed to read length");

    int total_offset = type_size + lenght_size + length;
    if (ftell(file) == total_offset) {
        if (fseek(file, 0, SEEK_SET) != 0) return genError("Failed to get to the start of the file");
    } else {
        if (fseek(file, -total_offset, SEEK_END) != 0) return genError("Failed to get to message start");
    }

    return length;
}

bool
MessagingBufferComponent::Impl::readBytes(FILE *file, uint size_to_read, char *output)
{
    for (uint index = 0; index < size_to_read; ++index) {
        int ch = fgetc(file);
        if (ch == EOF) return false;
        output[index] = static_cast<char>(ch);
    }
    return true;
}

Maybe<uint>
MessagingBufferComponent::Impl::getDirectorySize() const
{
    DIR *dir = opendir(buffer_root_path.c_str());
    if (dir == nullptr) {
        return genError("Unable to open directory: " + buffer_root_path);
    }

    uint total_size = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG) {
            struct stat file_info;
            string tmp_file_path = buffer_root_path + "/" + entry->d_name;
            if (stat(tmp_file_path.c_str(), &file_info) == 0) {
                total_size += file_info.st_size;
            } else {
                return genError("Error retrieving file size. " + tmp_file_path);
            }
        }
    }

    closedir(dir);
    return total_size;
}

// LCOV_EXCL_START  - Converting old formats to new format will be added later
Maybe<HTTPMethod>
MessagingBufferComponent::Impl::convertStringToHTTPMethod(const string &method_string)
{
    if (method_string == "GET") {
        return HTTPMethod::GET;
    } else if (method_string == "POST") {
        return HTTPMethod::POST;
    } else if (method_string == "PATCH") {
        return HTTPMethod::PATCH;
    } else if (method_string == "CONNECT") {
        return HTTPMethod::CONNECT;
    } else if (method_string == "PUT") {
        return HTTPMethod::PUT;
    } else {
        return genError("Unknown HTTP method");
    }
}

Maybe<HTTPRequestEvent>
MessagingBufferComponent::Impl::serializeOldData(const string &data)
{
    try {
        stringstream in;
        in.str(data);
        cereal::JSONInputArchive in_ar(in);

        HTTPRequestEvent req;
        req.load(in_ar);
        return req;
    } catch (cereal::Exception &e) {
        return genError("JSON parsing failed: " + string(e.what()));
    } catch (exception &e) {
        return genError(e.what());
    }
}

void
MessagingBufferComponent::Impl::convertLegacyBuffer(const string &body_file_path)
{
    ifstream file(body_file_path);
    if (!file.is_open()) {
        dbgTrace(D_MESSAGING_BUFFER) << "No body file found: " << body_file_path;
        return;
    }

    string request;
    while (getline(file, request)) {
        auto http_request_event = serializeOldData(encryptor->base64Decode(request));
        if (!http_request_event.ok()) {
            dbgWarning(D_MESSAGING_BUFFER) << "Error to serialize http_request_event: " << http_request_event.getErr();
            continue;
        }

        auto http_method = convertStringToHTTPMethod(http_request_event.unpack().getMethod());
        if (!http_method.ok()) {
            dbgWarning(D_MESSAGING_BUFFER) << "Error to convert http_method: " << http_method.getErr();
            continue;
        }

        pushNewBufferedMessage(
            http_request_event.unpack().getBody(),
            http_method.unpack(),
            http_request_event.unpack().getURL(),
            MessageCategory::GENERIC,
            MessageMetadata(),
            true
        );
    }
}

void
MessagingBufferComponent::Impl::removeLegacyBuffer(const string &root_path, const string &executable_name)
{
    string file_path = root_path + "manager" + executable_name;
    ifstream file(file_path);
    if (!file.is_open()) {
        dbgTrace(D_MESSAGING_BUFFER) << "No legacy MessagingBuffer buffers found: " << file_path;
        return;
    }

    string line;
    while (getline(file, line)) {
        dbgTrace(D_MESSAGING_BUFFER) << "Line: " << line;
        string body_file_path = root_path + line + executable_name;
        convertLegacyBuffer(body_file_path);
        if (remove(body_file_path.c_str()) == 0) {
            dbgDebug(D_MESSAGING_BUFFER) << "File successfully removed: " << body_file_path;
        } else {
            dbgWarning(D_MESSAGING_BUFFER) << "Failed to remove file: " << body_file_path;
        }
    }

    file.close();
    if (remove(file_path.c_str()) == 0) {
        dbgDebug(D_MESSAGING_BUFFER) << "Manager file successfully removed: " << file_path;
    } else {
        dbgWarning(D_MESSAGING_BUFFER) << "Failed to remove file manager: " << file_path;
    }
}
// LCOV_EXCL_STOP

bool
MessagingBufferComponent::Impl::canWriteToDisk(size_t message_size) const
{
    dbgTrace(D_MESSAGING_BUFFER) << "Handling buffer size in disk";
    auto maybe_directory_size = getDirectorySize();
    if (!maybe_directory_size.ok()) {
        dbgWarning(D_MESSAGING_BUFFER) << "Failed to get directory size. " << maybe_directory_size.getErr();
        return false;
    }
    if ((*maybe_directory_size + message_size) < (max_size_on_disk_MB * 1024 * 1024)) {
        return true;
    }

    dbgWarning(D_MESSAGING_BUFFER)
        << "Buffer size is full. Directry size: "
        << *maybe_directory_size
        << ", Message size: "
        << message_size
        << ", Max size: "
        << max_size_on_disk_MB * 1024 * 1024;
    return false;
}

void
MessagingBufferComponent::init()
{
    pimpl->init();
}

MessagingBufferComponent::MessagingBufferComponent() : pimpl(make_unique<Impl>())
{}

MessagingBufferComponent::~MessagingBufferComponent()
{}
