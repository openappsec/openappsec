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

#include <unordered_map>

#include "messaging_downloader_client.h"
#include "i_messaging.h"
#include "config.h"
#include "rest.h"

USE_DEBUG_FLAG(D_COMMUNICATION);

using namespace std;

class MessagingDownloaderClientRequest : public ClientRest
{
public:
    MessagingDownloaderClientRequest()
    {
        file_name = "";
        url = "";
        port = 80;
        response_port = 0;
        status = false;
    }

    MessagingDownloaderClientRequest(
        const string &_file_name,
        const string &_url,
        const unsigned int _port,
        const unsigned int _response_port
    ) :
        file_name(_file_name),
        url(_url),
        port(_port),
        response_port(_response_port),
        status(false)
    {}

    bool getStatus() const { return status.get(); }
    const string & getUuid() const { return uuid.get(); }

    C2S_PARAM(string, file_name);
    C2S_PARAM(string, url);
    C2S_PARAM(unsigned int, port);
    C2S_PARAM(unsigned int, response_port);

    S2C_PARAM(string, uuid);
    S2C_PARAM(bool, status);
};

class DownloaderCbHandler
{
public:
    void
    addCallback(const string &uuid, I_MessagingDownloader::OnCompleteCB &cb)
    {
        DownloaderCbHandler::uuid_to_cb[uuid] = cb;
    }

    static void
    handleDownloadCB(const string &uuid, Maybe<string> &downloaded_file)
    {
        dbgTrace(D_COMMUNICATION) << "Handling downloading complete callback. UUID: " << uuid;
        if(DownloaderCbHandler::uuid_to_cb.find(uuid) == DownloaderCbHandler::uuid_to_cb.end()) {
            dbgWarning(D_COMMUNICATION) << "Failed to execute download completion callback.";
            return;
        }
        if (DownloaderCbHandler::uuid_to_cb.at(uuid) != nullptr) {
            DownloaderCbHandler::uuid_to_cb.at(uuid)(downloaded_file);
            DownloaderCbHandler::uuid_to_cb.erase(uuid);
        } else {
            string curr_status;
            if (downloaded_file.ok()) {
                curr_status = ". File path: " + downloaded_file.unpack();
            } else {
                curr_status = ". Error: " + downloaded_file.getErr();
            }
            dbgWarning(D_COMMUNICATION)
                << "Illegal download completion callback for downloading process with UUID: "
                << uuid
                << curr_status;
        }
        dbgTrace(D_COMMUNICATION) << "Successfully handled the downloading complete callback. UUID: " << uuid;
    }

    static unordered_map<string, I_MessagingDownloader::OnCompleteCB> uuid_to_cb;
};

unordered_map<string, I_MessagingDownloader::OnCompleteCB> DownloaderCbHandler::uuid_to_cb;

class MessagingDownloaderClientRes : public ServerRest
{
public:
    void
    doCall() override
    {
        dbgTrace(D_COMMUNICATION) << "Received response from the downloading server.";
        if (status.get() && filepath.isActive()) {
            Maybe<string> response(filepath.get());
            DownloaderCbHandler::handleDownloadCB(uuid.get(), response);
        } else {
            if (!error.isActive()) error = "unknown error";
            dbgWarning(D_COMMUNICATION) << "Failed to download. Error: " << error.get();
            Maybe<string> response = genError(error.get());
            DownloaderCbHandler::handleDownloadCB(uuid.get(), response);
        }
    }

    C2S_PARAM(string, uuid);
    C2S_PARAM(bool, status);
    C2S_OPTIONAL_PARAM(string, filepath);
    C2S_OPTIONAL_PARAM(string, error);
};

class MessagingDownloaderClient::Impl : Singleton::Provide<I_MessagingDownloader>::From<MessagingDownloaderClient>
{
public:
    void
    init()
    {
        i_msg = Singleton::Consume<I_Messaging>::by<MessagingDownloaderClient>();
        Singleton::Consume<I_RestApi>::by<MessagingDownloaderClient>()->addRestCall<MessagingDownloaderClientRes>(
            RestAction::SHOW,
            "download-status"
        );
    }

    void
    fini()
    {
        i_msg = nullptr;
    }

    bool
    downloadFile(
        const string &file_name,
        const string &url,
        I_MessagingDownloader::OnCompleteCB cb = nullptr,
        const unsigned int port = 0
    ) override
    {
        dbgTrace(D_COMMUNICATION)
            << "Processing new download request."
            << "File name: "
            << file_name
            << "URL: "
            << url;

        auto response_port = Singleton::Consume<I_Environment>::by<MessagingDownloaderClient>()->get<int>(
            "Listening Port"
        );

        if (!response_port.ok()) {
            dbgWarning(D_COMMUNICATION) << "Failed to get the service listening port.";
            return false;
        }

        vector<int> download_ports = {
            getConfigurationWithDefault(8164, "Downloader", "Downloader Primary Port"),
            getConfigurationWithDefault(8167, "Downloader", "Downloader Secondary Port")
        };

        MessagingDownloaderClientRequest download_obj(
            file_name,
            url,
            port,
            response_port.unpack()
        );
        Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::EXPECT_REPLY);
        if (i_msg != nullptr) {
            dbgTrace(D_COMMUNICATION) << "Sending request to the downloading service.";
            bool res = false;
            for (int port: download_ports) {
                dbgTrace(D_COMMUNICATION) << "Trying to request downloading with downloading service port " << port;
                res = i_msg->sendObject(
                    download_obj,
                    I_Messaging::Method::POST,
                    "127.0.0.1",
                    port,
                    conn_flags,
                    "/add-download-file"
                );
                if (res) break;
            }

            if (!res) {
                dbgInfo(D_COMMUNICATION) << "Failed to request for file downloading";
                return false;
            }
            dbgTrace(D_COMMUNICATION) << "Successfully requested for downloading.";
            cb_handler.addCallback(download_obj.getUuid(), cb);
        } else {
            dbgDebug(D_COMMUNICATION) << "Failed to request downloading. Illegal messaging infrastructure.";
        }
        return download_obj.getStatus();
    }

private:
    I_Messaging *i_msg;
    DownloaderCbHandler cb_handler;
};

MessagingDownloaderClient::MessagingDownloaderClient()
        :
    Component("MessagingDownloaderClient"),
    pimpl(make_unique<Impl>())
{}
MessagingDownloaderClient::~MessagingDownloaderClient() {}

void MessagingDownloaderClient::init() { pimpl->init(); }
void MessagingDownloaderClient::fini() { pimpl->fini(); }

void
MessagingDownloaderClient::preload()
{
    registerExpectedConfiguration<int>("Downloader", "Downloader Primary Port");
    registerExpectedConfiguration<int>("Downloader", "Downloader Secondary Port");
};
