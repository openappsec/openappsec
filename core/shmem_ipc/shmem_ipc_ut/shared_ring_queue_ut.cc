#include "../shared_ring_queue.h"

#include "cptest.h"
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;
using namespace testing;

// Extern the static variables from shared_ring_queue.c so we can reset them for testing
extern "C" {
    extern int g_effective_size_initialized;
    extern uint16_t g_effective_segment_size;
    extern uint16_t g_effective_entry_size;
}

const static string bad_shmem_path = "/root/sadsadsadad/444";
const static string valid_shmem_path = "shmem_ut2";
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);
const static uint16_t num_of_shmem_elem = 11;

class SharedRingQueueTest : public Test
{
public:
    SharedRingQueueTest()
    {
        string effective_size_str = to_string(SHARED_MEMORY_SEGMENT_ENTRY_SIZE);
        setenv("EFFECTIVE_SHM_SEGMENT_SIZE", effective_size_str.c_str(), 1);
        setenv("INFINITY_NEXT_NANO_AGENT", "TRUE", 1);
        
        owners_queue = createSharedRingQueue(valid_shmem_path.c_str(), num_of_shmem_elem, 1, 1);
        users_queue = createSharedRingQueue(valid_shmem_path.c_str(), num_of_shmem_elem, 0, 0);
    }

    ~SharedRingQueueTest()
    {
        if (owners_queue != nullptr) destroySharedRingQueue(owners_queue, 1, 1);
        if (users_queue != nullptr) destroySharedRingQueue(users_queue, 0, 0);
        owners_queue = nullptr;
        users_queue = nullptr;
    }

    SharedRingQueue *owners_queue = nullptr;
    SharedRingQueue *users_queue = nullptr;
};

TEST_F(SharedRingQueueTest, init_queues)
{
    EXPECT_NE(owners_queue, nullptr);
    EXPECT_NE(users_queue, nullptr);
}

TEST_F(SharedRingQueueTest, basic_write_read_pop_transaction)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);
    const char data_to_write[] = "my basic_write_read_pop_transaction test data";
    const char *read_data;
    uint16_t read_bytes = 0;
    EXPECT_EQ(pushToQueue(users_queue, data_to_write, sizeof(data_to_write)), 0);
    EXPECT_EQ(peekToQueue(owners_queue, &read_data, &read_bytes), 0);
    EXPECT_STREQ(read_data, data_to_write);
    EXPECT_EQ(read_bytes, sizeof(data_to_write));
    EXPECT_EQ(popFromQueue(owners_queue), 0);
}

TEST_F(SharedRingQueueTest, multiple_write_read_pop_transactions)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);
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
        EXPECT_EQ(pushToQueue(users_queue, data.c_str(), data.size()), 0);
    }
    const char *read_buff = nullptr;
    uint16_t read_bytes = 0;
    vector<string> read_data;
    while (!isQueueEmpty(owners_queue)) {
        ASSERT_LT(read_data.size(), data_to_write.size());
        EXPECT_EQ(peekToQueue(owners_queue, &read_buff, &read_bytes), 0);
        read_data.push_back(string(read_buff, read_bytes));
        EXPECT_EQ(popFromQueue(owners_queue), 0);
    }
    EXPECT_EQ(read_data, data_to_write);
}

// reduced padding to 1 in order to allow comparing sizeof this struct with actually read data
#pragma pack(1)
struct my_multi_elem_struct {
    int my_int;
    char my_char;
    char my_string[4];
    char my_array[6];
};

struct my_multi_elem_struct
createMyStruct(int my_int, char my_char, const char *my_string, const char *my_array)
{
    struct my_multi_elem_struct my_struct;
    my_struct.my_int = my_int;
    my_struct.my_char = my_char;
    strncpy(my_struct.my_string, my_string, 4);
    strncpy(my_struct.my_array, my_array, 6);
    return my_struct;
}

bool
operator==(const struct my_multi_elem_struct &first, const struct my_multi_elem_struct &second)
{
    return first.my_int == second.my_int &&
        first.my_char == second.my_char &&
        strncmp(first.my_string, second.my_string, 4) == 0 &&
        strncmp(first.my_array, second.my_array, 6) == 0;
}

TEST_F(SharedRingQueueTest, write_read_pop_mulltiple_elements_transaction)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);
    int my_first_int = 1;
    int my_second_int = 2;
    char my_first_char = '1';
    char my_second_char = '2';
    string my_first_string = "one";
    string my_second_string = "two";
    const char my_first_array[] = { '1', 'o', 'n', 'e', '!', '\0' };
    const char my_second_array[] = { '@', 't', 'w', 'o', '2', '\0' };

    vector<const char *> data1 = {
        reinterpret_cast<const char *>(&my_first_int),
        const_cast<const char *>(&my_first_char),
        const_cast<const char *>(my_first_string.data()),
        my_first_array
    };
    vector<uint16_t> sizes1 = {
        sizeof(my_first_int),
        sizeof(my_first_char),
        static_cast<uint16_t>(my_first_string.size() + 1),
        sizeof(my_first_array)
    };

    vector<const char *> data2 = {
        reinterpret_cast<const char *>(&my_second_int),
        const_cast<const char *>(&my_second_char),
        const_cast<const char *>(my_second_string.data()),
        my_second_array
    };
    vector<uint16_t> sizes2 = {
        sizeof(my_second_int),
        sizeof(my_second_char),
        static_cast<uint16_t>(my_second_string.size() + 1),
        sizeof(my_second_array)
    };

    EXPECT_EQ(pushBuffersToQueue(users_queue, data1.data(), sizes1.data(), data1.size()), 0);
    EXPECT_EQ(pushBuffersToQueue(users_queue, data2.data(), sizes2.data(), data2.size()), 0);

    const char *read_buff = nullptr;
    uint16_t read_bytes = 0;
    EXPECT_EQ(peekToQueue(owners_queue, &read_buff, &read_bytes), 0);
    struct my_multi_elem_struct expected_data = createMyStruct(
        my_first_int,
        my_first_char,
        my_first_string.data(),
        my_first_array
    );
    ASSERT_EQ(read_bytes, sizeof(expected_data));
    const struct my_multi_elem_struct actual_data = *reinterpret_cast<const struct my_multi_elem_struct *>(read_buff);
    EXPECT_TRUE(actual_data == expected_data);
    EXPECT_EQ(popFromQueue(owners_queue), 0);
    EXPECT_EQ(peekToQueue(owners_queue, &read_buff, &read_bytes), 0);
    expected_data = createMyStruct(my_first_int, my_first_char, my_first_string.data(), my_first_array);
    ASSERT_EQ(read_bytes, sizeof(expected_data));
    EXPECT_EQ(popFromQueue(owners_queue), 0);
}

TEST_F(SharedRingQueueTest, write_read_pop_over_multiple_segments)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    vector<vector<char>> data = {
        vector<char>(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '1'),
        vector<char>(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '2'),
        vector<char>(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '3'),
        vector<char>(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '4'),
        vector<char>(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '5')
    };

    for (const vector<char> &long_buffer : data) {
        EXPECT_EQ(pushToQueue(users_queue, long_buffer.data(), long_buffer.size()), 0);
    }

    vector<char> no_more_space_data(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*2, '6');
    EXPECT_EQ(pushToQueue(users_queue, no_more_space_data.data(), no_more_space_data.size()), -3);

    const char *read_data = nullptr;
    uint16_t read_bytes = 0;
    for (const vector<char> &long_buffer : data) {
        EXPECT_EQ(peekToQueue(owners_queue, &read_data, &read_bytes), 0);
        EXPECT_EQ(string(read_data, read_bytes), string(long_buffer.data(), long_buffer.size()));
        EXPECT_EQ(popFromQueue(owners_queue), 0);
    }

    EXPECT_TRUE(isQueueEmpty(owners_queue));
    EXPECT_TRUE(isQueueEmpty(users_queue));
}

TEST_F(SharedRingQueueTest, write_element_that_fills_the_entire_queue)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    vector<char> short_data(100, '1');
    vector<char> long_data(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*(num_of_shmem_elem - 1), '2');

    EXPECT_EQ(pushToQueue(users_queue, long_data.data(), long_data.size()), 0);
    EXPECT_EQ(pushToQueue(users_queue, short_data.data(), short_data.size()), -3);

    const char *data_to_read = nullptr;
    uint16_t read_bytes = 0;
    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), 0);
    EXPECT_EQ(read_bytes, long_data.size());
    EXPECT_EQ(popFromQueue(owners_queue), 0);

    EXPECT_EQ(pushToQueue(users_queue, long_data.data(), long_data.size()), -3);
    EXPECT_EQ(pushToQueue(users_queue, short_data.data(), short_data.size()), 0);

    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), 0);
    EXPECT_EQ(read_bytes, short_data.size());
    EXPECT_EQ(popFromQueue(owners_queue), 0);
}

TEST_F(SharedRingQueueTest, not_enought_space_to_push_on_end_but_enought_on_start)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    vector<char> short_data(SHARED_MEMORY_SEGMENT_ENTRY_SIZE/2, '1');
    vector<char> long_data(SHARED_MEMORY_SEGMENT_ENTRY_SIZE*3, '2');

    for (uint i = 0; i < num_of_shmem_elem - 1; i++) {
        EXPECT_EQ(pushToQueue(users_queue, short_data.data(), short_data.size()), 0);
    }
    EXPECT_EQ(pushToQueue(users_queue, long_data.data(), long_data.size()), -3);

    for (uint i = 0; i < 3; i++) {
        EXPECT_EQ(popFromQueue(owners_queue), 0);
        EXPECT_EQ(pushToQueue(users_queue, long_data.data(), long_data.size()), -3);
    }

    EXPECT_EQ(popFromQueue(owners_queue), 0);
    EXPECT_EQ(pushToQueue(users_queue, long_data.data(), long_data.size()), 0);
}

TEST_F(SharedRingQueueTest, attempt_write_to_full_queue)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    int data_to_write = 100;
    for (uint i = 0; i < num_of_shmem_elem - 1; i ++) {
        EXPECT_EQ(pushToQueue(users_queue, reinterpret_cast<char *>(&data_to_write), sizeof(data_to_write)), 0);
    }
    EXPECT_EQ(pushToQueue(users_queue, reinterpret_cast<char *>(&data_to_write), sizeof(data_to_write)), -3);

    const char *data_to_read = nullptr;
    uint16_t read_bytes = 0;
    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), 0);
    EXPECT_EQ(read_bytes, sizeof(data_to_write));
    EXPECT_EQ(*reinterpret_cast<const int *>(data_to_read), data_to_write);
    EXPECT_EQ(popFromQueue(owners_queue), 0);
    EXPECT_EQ(
        pushToQueue(users_queue, reinterpret_cast<char *>(&data_to_write), sizeof(data_to_write)),
        0
    );
    EXPECT_EQ(
        pushToQueue(users_queue, reinterpret_cast<char *>(&data_to_write), sizeof(data_to_write)),
        -3
    );

    int popped_items_count = 0;
    while (!isQueueEmpty(owners_queue)) {
        EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), 0);
        EXPECT_EQ(read_bytes, sizeof(data_to_write));
        EXPECT_EQ(*reinterpret_cast<const int *>(data_to_read), data_to_write);
        EXPECT_EQ(popFromQueue(owners_queue), 0);
        ASSERT_NE(popped_items_count, num_of_shmem_elem);
        popped_items_count++;
    }
}

TEST_F(SharedRingQueueTest, attempt_to_read_and_pop_from_empty_queue)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    EXPECT_TRUE(isQueueEmpty(owners_queue));
    EXPECT_TRUE(isQueueEmpty(users_queue));

    const char *data_to_read = nullptr;
    uint16_t read_bytes = 0;
    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), -1);
    EXPECT_EQ(popFromQueue(owners_queue), -1);

    EXPECT_EQ(pushToQueue(users_queue, "abcd", 5), 0);
    EXPECT_FALSE(isQueueEmpty(owners_queue));
    EXPECT_FALSE(isQueueEmpty(users_queue));
    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), 0);
    EXPECT_EQ(popFromQueue(owners_queue), 0);

    EXPECT_EQ(read_bytes, 5);
    EXPECT_STREQ(data_to_read, "abcd");

    EXPECT_TRUE(isQueueEmpty(owners_queue));
    EXPECT_TRUE(isQueueEmpty(users_queue));
    EXPECT_EQ(peekToQueue(owners_queue, &data_to_read, &read_bytes), -1);
    EXPECT_EQ(popFromQueue(owners_queue), -1);
}

TEST_F(SharedRingQueueTest, ilegal_queue)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    destroySharedRingQueue(users_queue, 0, 1);
    users_queue = createSharedRingQueue(valid_shmem_path.c_str(), max_num_of_data_segments + 1, 0, 0);
    EXPECT_EQ(users_queue, nullptr);

    users_queue = createSharedRingQueue(bad_shmem_path.c_str(), max_num_of_data_segments, 0, 0);
    EXPECT_EQ(users_queue, nullptr);

    owners_queue = createSharedRingQueue(valid_shmem_path.c_str(), max_num_of_data_segments, 1, 1);
    EXPECT_NE(owners_queue, nullptr);
}

class EffectiveSegmentSizeTest : public Test
{
public:
    EffectiveSegmentSizeTest()
    {
        g_effective_size_initialized = 0;
        g_effective_segment_size = 0;
        g_effective_entry_size = 0;
    }

    ~EffectiveSegmentSizeTest()
    {
        unsetenv("EFFECTIVE_SHM_SEGMENT_SIZE");
        unsetenv("INFINITY_NEXT_NANO_AGENT");
        unlink("/dev/shm/attachment-metadata");
    }
};

TEST_F(EffectiveSegmentSizeTest, effective_segment_size_from_metadata_file)
{
    g_effective_size_initialized = 0;
    g_effective_segment_size = 0;
    g_effective_entry_size = 0;
    
    const string metadata_file_path = "/dev/shm/attachment-metadata";
    const string test_effective_size = "1024";
    const string test_queue_name = "metadata_file_test_queue";
    
    unsetenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    setenv("INFINITY_NEXT_NANO_AGENT", "TRUE", 1);
    unlink(metadata_file_path.c_str());
    
    {
        ofstream metadata_file(metadata_file_path);
        ASSERT_TRUE(metadata_file.is_open()) << "Failed to create metadata file at " << metadata_file_path;
        metadata_file << "EFFECTIVE_SHM_SEGMENT_SIZE=" << test_effective_size << endl;
        metadata_file << "# This is a test metadata file" << endl;
        metadata_file.close();
    }
    
    struct stat file_stat;
    ASSERT_EQ(stat(metadata_file_path.c_str(), &file_stat), 0) << "Metadata file was not created successfully";
    
    {
        ifstream metadata_file(metadata_file_path);
        ASSERT_TRUE(metadata_file.is_open());
        string line;
        getline(metadata_file, line);
        EXPECT_EQ(line, "EFFECTIVE_SHM_SEGMENT_SIZE=" + test_effective_size) << "Metadata file content is incorrect";
        metadata_file.close();
    }
    
    SharedRingQueue *test_owners_queue = createSharedRingQueue(test_queue_name.c_str(), 5, 1, 1);
    SharedRingQueue *test_users_queue = createSharedRingQueue(test_queue_name.c_str(), 5, 0, 0);
    
    ASSERT_NE(test_owners_queue, nullptr) << "Failed to create owner queue";
    ASSERT_NE(test_users_queue, nullptr) << "Failed to create user queue";
    
    const char* env_effective_size = getenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    ASSERT_NE(env_effective_size, nullptr)
        << "EFFECTIVE_SHM_SEGMENT_SIZE environment variable was not set from metadata file";
    EXPECT_STREQ(env_effective_size, test_effective_size.c_str())
        << "Environment variable value does not match expected value";

    EXPECT_EQ(g_effective_segment_size, 1024) << "Effective segment size should be 1024";
    
    const char test_data[] = "Metadata file test data";
    const char *read_data;
    uint16_t read_bytes = 0;
    
    EXPECT_EQ(pushToQueue(test_users_queue, test_data, sizeof(test_data)), 0);
    EXPECT_FALSE(isQueueEmpty(test_owners_queue));
    EXPECT_EQ(peekToQueue(test_owners_queue, &read_data, &read_bytes), 0);
    EXPECT_EQ(read_bytes, sizeof(test_data));
    EXPECT_STREQ(read_data, test_data);
    EXPECT_EQ(popFromQueue(test_owners_queue), 0);
    EXPECT_TRUE(isQueueEmpty(test_owners_queue));
    
    destroySharedRingQueue(test_owners_queue, 1, 1);
    destroySharedRingQueue(test_users_queue, 0, 0);
    unlink(metadata_file_path.c_str());
}

TEST_F(EffectiveSegmentSizeTest, effective_segment_size_from_environment_variable)
{
    g_effective_size_initialized = 0;
    g_effective_segment_size = 0;
    g_effective_entry_size = 0;
    
    const string test_effective_size = "2048";
    const string test_queue_name = "env_effective_size_test_queue";
    
    setenv("EFFECTIVE_SHM_SEGMENT_SIZE", test_effective_size.c_str(), 1);
    setenv("INFINITY_NEXT_NANO_AGENT", "TRUE", 1);
    
    SharedRingQueue *test_owners_queue = createSharedRingQueue(test_queue_name.c_str(), 8, 1, 1);
    SharedRingQueue *test_users_queue = createSharedRingQueue(test_queue_name.c_str(), 8, 0, 0);
    
    ASSERT_NE(test_owners_queue, nullptr) << "Failed to create owner queue for environment variable test";
    ASSERT_NE(test_users_queue, nullptr) << "Failed to create user queue for environment variable test";
    
    const char* env_effective_size = getenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    ASSERT_NE(env_effective_size, nullptr) << "EFFECTIVE_SHM_SEGMENT_SIZE environment variable was not set";
    EXPECT_STREQ(env_effective_size, test_effective_size.c_str())
        << "Environment variable value does not match expected value";

    EXPECT_EQ(g_effective_segment_size, 2048) << "Effective segment size should be 2048";
    
    string large_test_data(1500, 'X');
    const char *read_data;
    uint16_t read_bytes = 0;
    
    EXPECT_EQ(pushToQueue(test_users_queue, large_test_data.c_str(), large_test_data.size() + 1), 0);
    EXPECT_FALSE(isQueueEmpty(test_owners_queue));
    EXPECT_EQ(peekToQueue(test_owners_queue, &read_data, &read_bytes), 0);
    EXPECT_EQ(read_bytes, large_test_data.size() + 1);
    EXPECT_EQ(strncmp(read_data, large_test_data.c_str(), large_test_data.size()), 0);
    EXPECT_EQ(popFromQueue(test_owners_queue), 0);
    EXPECT_TRUE(isQueueEmpty(test_owners_queue));
    
    destroySharedRingQueue(test_owners_queue, 1, 1);
    destroySharedRingQueue(test_users_queue, 0, 0);
    
    unsetenv("EFFECTIVE_SHM_SEGMENT_SIZE");
    unsetenv("INFINITY_NEXT_NANO_AGENT");
}
