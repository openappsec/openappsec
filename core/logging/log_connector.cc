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

#include "log_streams.h"

void
LogStreamConnector::maintainConnection()
{
    dbgTrace(D_REPORT)
        << "Check if the connection is alive:"
        << (socket.ok() ? " socket ok" : " socket not ok")
        << (did_write_fail_in_this_window ? " previous write failed" : " previous write succeeded");
    if (!socket.ok() || did_write_fail_in_this_window) {
        dbgTrace(D_REPORT)
            << (socket.ok() ? "" : "The current socket is not ok, trying to connect.");
        connect();
        did_write_fail_in_this_window = false;
        if (!socket.ok()) {
            dbgWarning(D_REPORT) << "Failed to connect to the server, logs will not be sent";
            return;
        }
    }
}

void
LogStreamConnector::addLogToQueue(const std::vector<char> &data)
{
    if (logs_in_queue.size() < max_data_in_queue) {
        dbgTrace(D_REPORT)
            << "Adding log to queue, Amount of logs in queue: "
            << logs_in_queue.size();
        logs_in_queue.push_back(data);
    } else {
        dbgWarning(D_REPORT) << "Queue is full, dropping log";
    }
}

void
LogStreamConnector::writeFail()
{
    if (!socket.ok()) {
        dbgTrace(D_REPORT) << "Socket is not ok, stopping the connect after write failure";
        return;
    }
    dbgTrace(D_REPORT) << (did_write_fail_in_this_window ? "Previous write failed" : "Previous write succeeded");
    if (!did_write_fail_in_this_window) {
        dbgTrace(D_REPORT)
            << "First time in window that write failed, trying to reconnect to server";
        connect();
    }
    did_write_fail_in_this_window = true;
}

bool
LogStreamConnector::basicWriteLog(const std::vector<char> &data)
{
    for (size_t tries = 0; tries < 3; tries++) {
        if (socket.ok() && i_socket->writeData(socket.unpack(), data)) {
            dbgTrace(D_REPORT) << "log was sent to server";
            return true;
        } else {
            dbgTrace(D_REPORT) << "Failed to send log to server";
            writeFail();
        }
    }
    return false;
}

void
LogStreamConnector::sendLogWithQueue(const std::vector<char> &data)
{
    if (!socket.ok()) {
        dbgTrace(D_REPORT)
            << "Socket not ok. Size of logs in queue: "
            << logs_in_queue.size()
            << ". Adding logs to the queue until the connection is established.";
        addLogToQueue(data);
        return;
    }

    if (logs_in_queue.empty() && basicWriteLog(data)) return;

    addLogToQueue(data);

    int write_iterations = 0;
    
    while (write_iterations < max_logs_per_send && !logs_in_queue.empty()) {
        dbgTrace(D_REPORT)
            << " Iteration: "
            << write_iterations
            << " to try and write a log from queue to server"
            << log_name;
        int i = 0;
        bool write_success = false;
        while (
            socket.ok() &&
            (i < 3) &&
            !(write_success = i_socket->writeData(socket.unpack(), logs_in_queue.front()))) {
            i++;
        }
        if (write_success) {
            dbgTrace(D_REPORT) << "log was written to " << log_name << " server";
            logs_in_queue.erase(logs_in_queue.begin());
            write_iterations++;
        } else {
            dbgTrace(D_REPORT) << "Failed to send log to " << log_name << " server";
            writeFail();
            return;
        }
    }
}

void
LogStreamConnector::sendAllLogs()
{
    dbgTrace(D_REPORT) << "Sending all logs from queue to server";
    for(auto &log : logs_in_queue) {
        basicWriteLog(log);
    }
    logs_in_queue.clear();
}
