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

#include "messaging_downloader_server.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <sstream>
#include <set>

#include "i_messaging.h"
#include "rest.h"
#include "config.h"
#include "url_parser.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_COMMUNICATION);

using namespace std;

class MessagingDownloaderResponser : public ClientRest
{
public:
    MessagingDownloaderResponser()=delete;

    MessagingDownloaderResponser(string &_uuid, const Maybe<string> &_filepath)
            :
        uuid(_uuid),
        status(_filepath.ok())
    {
        if (_filepath.ok()) {
            filepath = _filepath.unpack();
        } else {
            error = _filepath.getErr();
        }
    }
    C2S_PARAM(string, uuid);
    C2S_PARAM(bool, status);
    C2S_OPTIONAL_PARAM(string, filepath)
    C2S_OPTIONAL_PARAM(string, error)
};

class MessagingDownloaderReceiver : public ServerRest
{
public:
    void
    doCall() override
    {
        dbgTrace(D_COMMUNICATION) << "Received new downloading request.";

        stringstream uuid_ss;
        uuid_ss << boost::uuids::random_generator()();
        uuid = uuid_ss.str();

        if (!port.isActive()) {
            dbgTrace(D_COMMUNICATION) << "Request does not contain explicit port.";
            port = 0;
        }

        dbgInfo(D_COMMUNICATION)
            << "Downloading a file and using the next parameters: "
            << "file_name: "
            << file_name.get()
            << ", url: "
            << url.get()
            << ", uuid: "
            << uuid.get()
            << ", port: "
            << port.get()
            << ", notification port: "
            << response_port.get();

        unsigned int response_port_cap = response_port.get();
        string uuid_capture = uuid.get();
        status = Singleton::Consume<I_MessagingDownloader>::from<MessagingDownloaderServer>()->downloadFile(
            file_name.get(),
            url.get(),
            [uuid_capture, response_port_cap](const Maybe<string> &downloaded_file) mutable
            {
                Flags<MessageConnConfig> conn_flags;
                MessagingDownloaderResponser res(uuid_capture, downloaded_file);
                dbgTrace(D_COMMUNICATION) << "Sending the download status to the client.";
                bool res_status = Singleton::Consume<I_Messaging>::by<MessagingDownloaderServer>()->sendNoReplyObject(
                    res,
                    I_Messaging::Method::POST,
                    "127.0.0.1",
                    response_port_cap,
                    conn_flags,
                    "/show-download-status"
                );
                if (!res_status) {
                    dbgInfo(D_COMMUNICATION) << "Failed to send the download status.";
                } else {
                    dbgDebug(D_COMMUNICATION)
                        << "Successfully sent the download status. Notification port: "
                        << response_port_cap
                        << ", Status: "
                        << downloaded_file.ok();
                }
            },
            port.get()
        );
    }

    C2S_PARAM(string, file_name);
    C2S_PARAM(string, url);
    C2S_PARAM(int, response_port);
    C2S_PARAM(int, port);
    S2C_PARAM(string, uuid);
    S2C_PARAM(bool, status);
};

class DownloadingInstance
{
public:
    DownloadingInstance()=default;

    DownloadingInstance(
        const string &_file_name,
        const string &_url,
        const unsigned int _port
    ) :
        file_name(_file_name),
        url(_url),
        port(_port),
        url_parser(_url)
    {
        parseURL();
    }

    Maybe<string>
    genJson() const
    {
        return string("");
    }

    bool
    loadJson(const string &_body)
    {
        body = vector<char>(_body.begin(), _body.end());
        return true;
    }

    const vector<char> &
    getResponse() const
    {
        return body;
    }

    bool
    operator==(const DownloadingInstance &other) const
    {
        return file_name == other.file_name &&
            host == other.host &&
            url == other.url &&
            port == other.port &&
            is_secure == other.is_secure &&
            origin_is_fog == other.origin_is_fog;
    }

    bool
    operator<(const DownloadingInstance &other) const
    {
        return file_name < other.file_name ||
            host < other.host ||
            url < other.url ||
            port < other.port ||
            is_secure < other.is_secure ||
            origin_is_fog < other.origin_is_fog;
    }

    const string & getFileName() const { return file_name; }
    const string & getHost() const { return host; }
    const string & getUrl() const { return url; }
    unsigned int getPort() const { return port; }
    bool getIsSecure() const { return is_secure; }
    bool getIsFogOrigin() const { return origin_is_fog; }

private:
    void
    parseURL()
    {
        dbgTrace(D_COMMUNICATION) << "Parsing the URL to extract the relevant info. URL: " << url;
        origin_is_fog = false;
        auto maybe_host = url_parser.getBaseURL();
        if (!maybe_host.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to parse the URL";
            return;
        }
        host = maybe_host.unpack();
        is_secure = url_parser.isOverSSL();
        if (port == 0 && url_parser.getPort() != "") {
            try {
                port = stoi(url_parser.getPort());
            } catch (exception &e) {
                port = 443;
                dbgInfo(D_COMMUNICATION)
                    << "Failed to parse the port for the downloading request. Error "
                    << e.what()
                    << ". Using the default port "
                    << port;
            }
        } else {
            dbgTrace(D_COMMUNICATION) << "Using explicitly defined port. Port: " << port;
        }

        I_AgentDetails *agent_details = Singleton::Consume<I_AgentDetails>::by<MessagingDownloaderServer>();
        if (agent_details->getFogDomain().ok()) {
            string fog_domain = agent_details->getFogDomain().unpack();
            if (host.find(fog_domain) != string::npos) {
                origin_is_fog = true;
            }
        } else {
            dbgTrace(D_COMMUNICATION) << "Failed to receive fog domain.";
        }
    }

    string file_name = "";
    string url = "";
    unsigned int port = 0;
    URLParser url_parser;
    vector<char> body = {};
    string host = "";
    bool is_secure = true;
    bool origin_is_fog = true;
};

class MessagingDownloaderServer::Impl : Singleton::Provide<I_MessagingDownloader>::From<MessagingDownloaderServer>
{
public:
    void
    init()
    {
        i_msg = Singleton::Consume<I_Messaging>::by<MessagingDownloaderServer>();
        i_mainloop = Singleton::Consume<I_MainLoop>::by<MessagingDownloaderServer>();
        auto rest = Singleton::Consume<I_RestApi>::by<MessagingDownloaderServer>();
        rest->addRestCall<MessagingDownloaderReceiver>(RestAction::ADD, "download-file");
        string default_downloading_dir = "/tmp/cp_nano_downloader/";
        download_dir = getConfigurationWithDefault(
            default_downloading_dir,
            "Downloader",
            "Downloading Directory"
        );
        NGEN::Filesystem::makeDirRecursive(download_dir);
    }

    void
    fini()
    {
        i_msg = nullptr;
        i_mainloop = nullptr;
    }

    bool
    downloadFile(
        const string &file_name,
        const string &url,
        OnCompleteCB on_complete_func = nullptr,
        const unsigned int port = 443
    ) override
    {
        dbgTrace(D_COMMUNICATION) << "Handling new download request. URL: " << url << ". File name: " << file_name;
        DownloadingInstance req(file_name, url, port);
        if (downloading_queue.find(req) != downloading_queue.end()) {
            dbgInfo(D_COMMUNICATION) << "Failed to download the file. Similar download request already exists.";
            return false;
        }
        if (!isValidPath(file_name)) {
            dbgInfo(D_COMMUNICATION) << "Failed to validate the download path. Path: " << download_dir + file_name;
            return false;
        }
        downloading_queue.insert(req);

        i_mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::RealTime,
            [this, req, on_complete_func]() mutable
            {
                Flags<MessageConnConfig> conn_flags;
                if (req.getIsSecure()) conn_flags.setFlag(MessageConnConfig::SECURE_CONN);
                if (!req.getIsFogOrigin()) conn_flags.setFlag(MessageConnConfig::EXTERNAL);
                auto on_exit = make_scope_exit([this, &req]() { downloading_queue.erase(req); } );
                bool response = i_msg->sendObject(
                    req,
                    I_Messaging::Method::GET,
                    req.getHost(),
                    req.getPort(),
                    conn_flags,
                    req.getUrl()
                );
                if (response) {
                    dbgTrace(D_COMMUNICATION) << "Successfully received a response from the downloading file host.";
                    std::ofstream downloaded_file;
                    downloaded_file.open(download_dir + req.getFileName());
                    if (!downloaded_file.is_open()) {
                        dbgInfo(D_COMMUNICATION)
                            << "Failed to download file. Error: Failed to open the file "
                            << req.getFileName();
                        Maybe<string> err = genError("Failed to open the file");
                        on_complete_func(err);
                        if (i_mainloop != nullptr) i_mainloop->yield(true);
                    }
                    auto &res_body = req.getResponse();
                    downloaded_file.write(res_body.data(), res_body.size());
                    downloaded_file.close();
                    dbgInfo(D_COMMUNICATION) << "Successfully downloaded the file. File name: " << req.getFileName();
                    Maybe<string> filepath = download_dir + req.getFileName();
                    on_complete_func(filepath);
                } else {
                    dbgInfo(D_COMMUNICATION) << "Failed to download file. File name: " << req.getFileName();
                    Maybe<string> err = genError("Failed during the downloading process.");
                    on_complete_func(err);
                }
            },
            "Download file routine for '" + file_name + "'",
            false
        );
        return true;
    }

private:
    bool
    isValidPath(const string &file_name)
    {
        struct stat info;
        string file_to_download = download_dir + file_name;
        dbgTrace(D_COMMUNICATION) << "Validating the downloading file path. Path: " << file_to_download;
        if (stat(download_dir.c_str(), &info) != 0) {
            dbgDebug(D_COMMUNICATION) << "Failed to access the downloading directory";
            return false;
        }
        if (stat(file_to_download.c_str(), &info) == 0) {
            dbgDebug(D_COMMUNICATION)
                << "The file with the name '"
                << file_name
                << "' is already exist in the downloading directory";
            return false;
        }
        return true;
    }

    I_Messaging *i_msg;
    I_MainLoop *i_mainloop;
    string download_dir;
    set<DownloadingInstance> downloading_queue;
};

MessagingDownloaderServer::MessagingDownloaderServer()
        :
    Component("MessagingDownloaderServer"),
    pimpl(make_unique<Impl>())
{}

MessagingDownloaderServer::~MessagingDownloaderServer() {}

void MessagingDownloaderServer::init() { pimpl->init(); }
void MessagingDownloaderServer::fini() { pimpl->fini(); }

void
MessagingDownloaderServer::preload()
{
    registerExpectedConfiguration<string>("Downloader", "Downloading Directory");
};
