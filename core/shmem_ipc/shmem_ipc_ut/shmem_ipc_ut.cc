#include "shmem_ipc.h"

#include <stdio.h>
#include <stdarg.h>

#include "../shared_ring_queue.h"
#include "debug.h"
#include "cptest.h"
#include "time_proxy.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_environment.h"

using namespace std;
using namespace testing;

const static string shmem_name = "shmem_ut";
const static uint16_t num_of_shmem_elem = 11;
const static size_t max_one_way_queue_name_length = 64;
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);
uint32_t uid = getuid();
uint32_t gid = getgid();

USE_DEBUG_FLAG(D_SHMEM);

void
debugFunc(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...)
{
    if (!Debug::evalFlags(Debug::DebugLevel::INFO, D_SHMEM)) return;

    va_list args;
    va_start(args, fmt);
    size_t len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    vector<char> message(len + 1);
    va_start(args, fmt);
    vsnprintf(&message[0], len + 1, fmt, args);
    va_end(args);

    Debug(
        file,
        func,
        line_num,
        is_error ? Debug::DebugLevel::WARNING : Debug::DebugLevel::TRACE,
        D_SHMEM
    ).getStreamAggr() << message.data();
}

class SharedIPCTest : public Test
{
public:
    SharedIPCTest()
    {
        Debug::setNewDefaultStdout(&capture_debug);
        Debug::setUnitTestFlag(D_SHMEM, Debug::DebugLevel::TRACE);
        owners_queue = initIpc(shmem_name.c_str(), uid, gid, 1, num_of_shmem_elem, debugFunc);
        users_queue = initIpc(shmem_name.c_str(), uid, gid, 0, num_of_shmem_elem, debugFunc);
    }

    ~SharedIPCTest()
    {
        if(owners_queue != nullptr) destroyIpc(owners_queue, 1);
        if(users_queue != nullptr) destroyIpc(users_queue, 0);
        owners_queue = nullptr;
        users_queue = nullptr;
        Debug::setNewDefaultStdout(&cout);
    }

    SharedMemoryIPC *owners_queue = nullptr;
    SharedMemoryIPC *users_queue = nullptr;
    stringstream capture_debug;
    TimeProxyComponent time_proxy;
    MockMainLoop mock_mainloop;
    MockEnvironment env;
};

TEST_F(SharedIPCTest, init_owner_queue)
{
    EXPECT_NE(owners_queue, nullptr);
    EXPECT_FALSE(isCorruptedShmem(owners_queue, 1));

    EXPECT_NE(users_queue, nullptr);
    EXPECT_FALSE(isCorruptedShmem(users_queue, 0));
}

TEST_F(SharedIPCTest, basic_write_read_pop_transaction)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    const string message = "my basic_write_read_pop_transaction test data";
    const string respond = "my basic_write_read_pop_transaction test data";

    const char *read_data = nullptr;
    uint16_t read_bytes = 0;

    EXPECT_EQ(sendData(owners_queue, message.size(), message.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(users_queue));
    EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_data), 0);
    EXPECT_EQ(string(read_data, read_bytes), message);
    EXPECT_EQ(popData(users_queue), 0);
    EXPECT_FALSE(isDataAvailable(users_queue));

    EXPECT_EQ(sendData(users_queue, respond.size(), respond.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_data), 0);
    EXPECT_EQ(string(read_data, read_bytes), respond);
    EXPECT_EQ(popData(owners_queue), 0);
    EXPECT_FALSE(isDataAvailable(owners_queue));
}

TEST_F(SharedIPCTest, memory_dump)
{
    const string message = "my basic_write_read_pop_transaction test data";
    sendData(owners_queue, message.size(), message.c_str());

    dumpIpcMemory(owners_queue);

    EXPECT_THAT(capture_debug.str(), HasSubstr("Ipc memory dump:"));
}

TEST_F(SharedIPCTest, ilegal_ipc)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    destroyIpc(owners_queue, 1);
    destroyIpc(users_queue, 0);

    owners_queue = initIpc("i/am/a/bad/shmem/path", uid, gid, 1, num_of_shmem_elem, debugFunc);
    users_queue = initIpc(shmem_name.c_str(), uid, gid, 0, max_num_of_data_segments + 1, debugFunc);

    EXPECT_EQ(owners_queue, nullptr);
    EXPECT_EQ(users_queue, nullptr);

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Failed to open shared memory for '__cp_nano_rx_shared_memory_i/am/a/bad/shmem/path__'")
    );

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Cannot create data segment with 513 elements (max number of elements is 512)")
    );
}

TEST_F(SharedIPCTest, multiple_write_read_pop_transactions)
{
    vector<string> data_to_write = {
        "my basic_write_read_pop_transaction test data0",
        "my basic_write_read_pop_transaction test data1",
        "my basic_write_read_pop_transaction test data2",
        "my basic_write_read_pop_transaction test data3",
        "my basic_write_read_pop_transaction test data4",
        "my basic_write_read_pop_transaction test data5",
        "my basic_write_read_pop_transaction test data6",
        "my basic_write_read_pop_transaction test data7",
        "my basic_write_read_pop_transaction test data8",
        "my basic_write_read_pop_transaction test data9"
    };
    for (const string &data : data_to_write) {
        EXPECT_EQ(sendData(users_queue, data.size(), data.c_str()), 0);
    }
    const char *read_buff = nullptr;
    uint16_t read_bytes = 0;
    vector<string> read_data;
    while (isDataAvailable(owners_queue)) {
        ASSERT_LT(read_data.size(), data_to_write.size());
        EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_buff), 0);
        read_data.push_back(string(read_buff, read_bytes));
        EXPECT_EQ(sendData(owners_queue, read_bytes, read_buff), 0);
        EXPECT_EQ(popData(owners_queue), 0);
    }

    EXPECT_EQ(read_data, data_to_write);
    for (uint i = 0; i < read_data.size(); i++) {
        EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_buff), 0);
        EXPECT_EQ(string(read_buff, read_bytes), read_data[i]);
        EXPECT_EQ(popData(users_queue), 0);
    }
}

TEST_F(SharedIPCTest, reset_shmem)
{
    string data_to_write = "my basic_write_read_pop_transaction test data";

    int count = 0;
    while (sendData(users_queue, data_to_write.size(), data_to_write.c_str()) == 0) {
        count++;
        ASSERT_NE(count, num_of_shmem_elem);
    }

    EXPECT_NE(sendData(users_queue, data_to_write.size(), data_to_write.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    resetIpc(owners_queue, num_of_shmem_elem);
    EXPECT_FALSE(isDataAvailable(owners_queue));
    EXPECT_EQ(sendData(users_queue, data_to_write.size(), data_to_write.c_str()), 0);
}

TEST_F(SharedIPCTest, write_read_pop_mulltiple_elements_transaction)
{
    int my_first_int = 1;
    int my_second_int = 20;
    int my_third_int = 300;
    int my_fourth_int = 4000;
    int my_fifth_int = 50000;

    char my_first_char = '1';
    char my_second_char = '2';
    char my_third_char = '3';
    char my_fourth_char = '4';
    char my_fifth_char = '5';

    vector<const char *> data1 = {
        reinterpret_cast<const char *>(&my_first_int),
        reinterpret_cast<const char *>(&my_second_int),
        reinterpret_cast<const char *>(&my_third_int),
        reinterpret_cast<const char *>(&my_fourth_int),
        reinterpret_cast<const char *>(&my_fifth_int)
    };
    vector<uint16_t> sizes1 = { sizeof(int), sizeof(int), sizeof(int), sizeof(int), sizeof(int) };

    vector<const char *> data2 = {
        const_cast<const char *>(&my_first_char),
        const_cast<const char *>(&my_second_char),
        const_cast<const char *>(&my_third_char),
        const_cast<const char *>(&my_fourth_char),
        const_cast<const char *>(&my_fifth_char)
    };
    vector<uint16_t> sizes2 = { sizeof(char), sizeof(char), sizeof(char), sizeof(char), sizeof(char) };

    const char *read_data = nullptr;
    uint16_t read_bytes = 0;

    EXPECT_EQ(sendChunkedData(owners_queue, sizes1.data(), data1.data(), data1.size()), 0);
    EXPECT_TRUE(isDataAvailable(users_queue));
    EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_data), 0);
    vector<int> expected_data = { my_first_int, my_second_int, my_third_int, my_fourth_int, my_fifth_int };
    vector<int> received_data(
        reinterpret_cast<const int *>(read_data),
        reinterpret_cast<const int *>(read_data) + read_bytes/sizeof(int)
    );
    EXPECT_EQ(received_data, expected_data);
    EXPECT_EQ(popData(users_queue), 0);
    EXPECT_FALSE(isDataAvailable(users_queue));

    EXPECT_EQ(sendChunkedData(users_queue, sizes1.data(), data1.data(), data1.size()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_data), 0);
    vector<char> expected_char_data = { my_first_char, my_second_char, my_third_char, my_fourth_char, my_fifth_char };
    vector<char> received_char_data(read_data, read_data + read_bytes/sizeof(char));
    EXPECT_EQ(received_data, expected_data);
    EXPECT_EQ(popData(owners_queue), 0);
    EXPECT_FALSE(isDataAvailable(owners_queue));
}

TEST_F(SharedIPCTest, ensure_right_permissions)
{
    char queue_name_tx[max_one_way_queue_name_length];
    char queue_name_rx[max_one_way_queue_name_length];
    snprintf(queue_name_tx, sizeof(queue_name_tx) - 1, "/dev/shm/__cp_nano_tx_shared_memory_%s__", shmem_name.c_str());
    snprintf(queue_name_rx, sizeof(queue_name_rx) - 1, "/dev/shm/__cp_nano_rx_shared_memory_%s__", shmem_name.c_str());
    for (char *queue_name : {queue_name_tx, queue_name_rx}) {
        struct stat info;
        stat(queue_name, &info);
        EXPECT_EQ(info.st_uid, uid);
        EXPECT_EQ(info.st_gid, gid);
        EXPECT_EQ(info.st_mode & S_IRUSR, S_IRUSR);
        EXPECT_EQ(info.st_mode & S_IWUSR, S_IWUSR);
        EXPECT_NE(info.st_mode & S_IXUSR, S_IXUSR);
    }
}
