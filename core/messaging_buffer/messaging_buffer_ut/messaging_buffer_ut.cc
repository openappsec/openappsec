#include "messaging_buffer.h"

#include <chrono>
#include <vector>
#include <memory>
#include <boost/filesystem.hpp>

#include "singleton.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "messaging_buffer/event_queue.h"
#include "messaging_buffer/http_request_event.h"

#include "cptest.h"
#include "mock/mock_instance_awareness.h"
#include "mock/mock_time_get.h"
#include "encryptor.h"
#include "mock/mock_mainloop.h"

using namespace testing;
using namespace std;

USE_DEBUG_FLAG(D_EVENT_BUFFER);

bool
operator==(const HTTPRequestEvent &a, const HTTPRequestEvent &b)
{
    return
        a.getBody() == b.getBody() &&
        a.getHeaders() == b.getHeaders() &&
        a.getMethod() == b.getMethod() &&
        a.getURL() == b.getURL();
}

class MessagingBufferTest : public Test
{
public:
    MessagingBufferTest()
    {
        mkdir("/tmp/event_buffer/", 0777);
        instance_awareness_value = "ia";
        process_name_value = "pn";
        Debug::setNewDefaultStdout(&capture_debug);
        EXPECT_CALL(instance_awareness, getUniqueID(_)).WillRepeatedly(Return(instance_awareness_value));
        i_messaging_buffer = Singleton::Consume<I_MessagingBuffer>::from(messaging_buffer);
        i_encryptor = Singleton::Consume<I_Encryptor>::from(encryptor);
        env.preload();
    }

    void
    init(bool proccess_name_value = true)
    {
        setConfiguration<string>("/tmp/event_buffer", "Event Buffer", "base folder");
        string process_path = "";
        if (proccess_name_value) process_path = "a/b/" + process_name_value;
        Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Executable Name", process_path);
        messaging_buffer.init();
    }

    ~MessagingBufferTest()
    {
        i_messaging_buffer->cleanBuffer();
        Debug::setNewDefaultStdout(&cout);
        boost::filesystem::path dir_path("/tmp/event_buffer/");
        remove_all(dir_path);
        rmdir(dir_path.filename().c_str());
    }

    I_MessagingBuffer *i_messaging_buffer;
    ostringstream capture_debug;
    string instance_awareness_value;
    string process_name_value;
    Encryptor encryptor;
    I_Encryptor *i_encryptor;
    StrictMock<MockTimeGet> timer;
    NaggyMock<MockMainLoop> mock_mainloop;
    StrictMock<MockInstanceAwareness> instance_awareness;
    MessagingBuffer messaging_buffer;

private:
    ::Environment env;
    ConfigComponent config;
};

TEST_F(MessagingBufferTest, doNothing)
{
}

TEST_F(MessagingBufferTest, init)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();
}

TEST_F(MessagingBufferTest, popRequestFromEmpty)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();
    auto req = i_messaging_buffer->peekRequest();
    EXPECT_FALSE(req.ok());
}

TEST_F(MessagingBufferTest, popRequestFromNonEmpty)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );

    init();
    auto empty_req = i_messaging_buffer->peekRequest();
    EXPECT_FALSE(empty_req.ok());

    HTTPRequestEvent req("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req);

    auto req_1 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_1.ok());
    i_messaging_buffer->popRequest();

    auto req_2 = i_messaging_buffer->peekRequest();
    EXPECT_FALSE(req_2.ok());
}

TEST_F(MessagingBufferTest, MultiRequestBuffering)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();

    HTTPRequestEvent req0123("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req0123);

    HTTPRequestEvent req0124("0", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req0124);

    HTTPRequestEvent req1124("1", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req1124);

    auto req_1 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_1.ok());
    i_messaging_buffer->popRequest();

    auto req_2 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_2.ok());
    i_messaging_buffer->popRequest();

    auto req_3 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_3.ok());
    i_messaging_buffer->popRequest();

    EXPECT_EQ(req_1.unpack(), req0123);
    EXPECT_EQ(req_2.unpack(), req0124);
    EXPECT_EQ(req_3.unpack(), req1124);
}

TEST_F(MessagingBufferTest, isPendingTrue)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(Return(chrono::microseconds(10000000)));
    init();

    HTTPRequestEvent req0123("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req0123);

    HTTPRequestEvent req0124("0", "1", "2", "4");

    EXPECT_TRUE(i_messaging_buffer->isPending(req0124));

    i_messaging_buffer->bufferNewRequest(req0124);

    HTTPRequestEvent req1124("1", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req1124);
}

TEST_F(MessagingBufferTest, isPendingFalse)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(Return(chrono::microseconds(10000000)));
    init();

    HTTPRequestEvent req0123("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req0123);

    HTTPRequestEvent req0124("0", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req0124);

    HTTPRequestEvent req1124("1", "1", "2", "4");

    EXPECT_FALSE(i_messaging_buffer->isPending(req1124));

    i_messaging_buffer->bufferNewRequest(req1124);
}

TEST_F(MessagingBufferTest, noPopGivesSameRequest)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(Return(chrono::microseconds(10000000)));
    init();

    HTTPRequestEvent req0123("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req0123);

    HTTPRequestEvent req0124("0", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req0124);

    HTTPRequestEvent req1124("1", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req1124);


    auto req_1 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_1.ok());

    auto req_2 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_2.ok());

    auto req_3 = i_messaging_buffer->peekRequest();
    EXPECT_TRUE(req_3.ok());

    EXPECT_EQ(req_1.unpack(), req0123);
    EXPECT_EQ(req_2.unpack(), req0123);
    EXPECT_EQ(req_3.unpack(), req0123);
}

TEST_F(MessagingBufferTest, nothingLeft)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();

    HTTPRequestEvent req0123("0", "1", "2", "3");
    i_messaging_buffer->bufferNewRequest(req0123);

    HTTPRequestEvent req0124("0", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req0124);

    HTTPRequestEvent req1124("1", "1", "2", "4");
    i_messaging_buffer->bufferNewRequest(req1124);


    i_messaging_buffer->popRequest();
    i_messaging_buffer->popRequest();
    i_messaging_buffer->popRequest();

    auto req_1 = i_messaging_buffer->peekRequest();
    EXPECT_FALSE(req_1.ok());
}

TEST_F(MessagingBufferTest, hugeBuffering)
{
    messaging_buffer.preload();
    setConfiguration<uint>(0, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();
    const size_t events_size = 499;
    vector<HTTPRequestEvent> events;

    for (size_t i = 0; i < events_size; i++) {
        events.push_back(HTTPRequestEvent("0", std::to_string(i/10), "2", std::to_string(i)));
        i_messaging_buffer->bufferNewRequest(events[i]);
    }

    for (size_t i = 0; i < events_size; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        ASSERT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), events[i]);
    }

    events.clear();
    for (size_t i = 0; i < events_size; i++) {
        events.push_back(HTTPRequestEvent("0", std::to_string(i/10), "2", std::to_string(i)));
        i_messaging_buffer->bufferNewRequest(events[i]);
    }

    for (size_t i = 0; i < events_size; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        ASSERT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), events[i]);
    }
}

TEST_F(MessagingBufferTest, rejectedBufferOk)
{
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();

    I_MainLoop::Routine timer_routine;
    EXPECT_CALL(mock_mainloop, addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        _,
        _,
        _
    )).WillOnce(DoAll(SaveArg<1>(&timer_routine), Return(0)));

    HTTPRequestEvent req("0", "1", "2", "2");
    const size_t events_size = 3;
    for (size_t i = 0; i < events_size; i++) {
        i_messaging_buffer->bufferNewRequest(req, true);
    }

    timer_routine();

    ifstream buffer_file(
        "/tmp/event_buffer/rejected_events" + instance_awareness_value + process_name_value
    );

    ASSERT_TRUE(buffer_file.is_open());

    string line;
    vector<string> file_content;
    while (getline(buffer_file, line)) {
        file_content.push_back(line);
    }
    buffer_file.close();
    ASSERT_FALSE(buffer_file.is_open());

    for (auto content_line: file_content) {
        HTTPRequestEvent rejected_req;
        stringstream in;
        in.str(content_line);
        cereal::JSONInputArchive in_ar(in);
        rejected_req.load(in_ar);
        EXPECT_EQ(rejected_req, req);
    }
}

TEST_F(MessagingBufferTest, startFromFile)
{
    string event_as_string;
    HTTPRequestEvent event("0", "1", "2", "3");

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        event.save(out_ar);
    }
    event_as_string = i_encryptor->base64Encode(out.str());

    ofstream write_initial_file(
        "/tmp/event_buffer/" + i_encryptor->base64Encode("01") + instance_awareness_value + process_name_value,
        ios_base::app
    );

    ofstream manager_file(
        "/tmp/event_buffer/manager" + instance_awareness_value + process_name_value, ios_base::app
    );

    ASSERT_TRUE(write_initial_file.is_open());
    ASSERT_TRUE(manager_file.is_open());
    for (int i = 0 ; i < 101 ; i++) {
        write_initial_file << event_as_string << "\n";
        manager_file << i_encryptor->base64Encode("01") << "\n";
    }

    write_initial_file.close();
    ASSERT_FALSE(write_initial_file.is_open());

    manager_file.close();
    ASSERT_FALSE(manager_file.is_open());

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();

    for (int i = 0 ; i < 101 ; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        EXPECT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), event);
    }

    i_messaging_buffer->bufferNewRequest(event);
}

TEST_F(MessagingBufferTest, PushToBufferedFile)
{
    messaging_buffer.preload();
    setConfiguration<uint>(0, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");

    string event_as_string;
    HTTPRequestEvent event("0", "1", "2", "3");

    stringstream out;
    {
        cereal::JSONOutputArchive out_ar(out);
        event.save(out_ar);
    }
    event_as_string = i_encryptor->base64Encode(out.str());

    ofstream write_initial_file(
        "/tmp/event_buffer/" + i_encryptor->base64Encode("01") + instance_awareness_value + process_name_value,
        ios_base::app
    );
    ofstream manager_file(
        "/tmp/event_buffer/manager" + instance_awareness_value + process_name_value, ios_base::app
    );

    ASSERT_TRUE(write_initial_file.is_open());
    ASSERT_TRUE(manager_file.is_open());
    for (int i = 0 ; i < 101 ; i++) {
        write_initial_file << event_as_string << "\n";
        manager_file << i_encryptor->base64Encode("01") << "\n";
    }

    write_initial_file.close();
    ASSERT_FALSE(write_initial_file.is_open());

    manager_file.close();
    ASSERT_FALSE(manager_file.is_open());

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();

    i_messaging_buffer->bufferNewRequest(event);
    for (int i = 0 ; i < 101 ; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        EXPECT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), event);
    }
}

TEST_F(MessagingBufferTest, max_buffer_size)
{
    messaging_buffer.preload();
    setConfiguration<uint>(0, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");
    ostringstream capture_debug;
    Debug::setNewDefaultStdout(&capture_debug);
    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                static int counter = 1;
                return chrono::microseconds(10000001 * (++counter));
            }
        )
    );
    init();

    vector<I_MainLoop::Routine> timer_routines;
    EXPECT_CALL(mock_mainloop, addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        _,
        _,
        _
    )).WillRepeatedly(
        WithArgs<1>(
            Invoke(
            [&](const I_MainLoop::Routine &routine)
            {
                timer_routines.push_back(routine);
                return 0;
            }
        )
    ));

    const size_t events_size = 3;
    vector<HTTPRequestEvent> events;
    for (size_t i = 0; i < events_size; i++) {
        events.push_back(
            HTTPRequestEvent(
                "0",
                to_string(i),
                "00",
                to_string(i)
            )
        );
        i_messaging_buffer->bufferNewRequest(events[i]);

        // Run all pending timers
        for (auto &routine : timer_routines) routine();
        timer_routines.clear();
    }
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Failed to buffer a message after reaching the maximum buffer size")
    );
}

class MessagingBufferFiniTest : public Test
{
public:
    MessagingBufferFiniTest()
    {
        messaging_buffer = make_unique<MessagingBuffer>();
        mkdir("/tmp/event_buffer/", 0777);
        instance_awareness_value = "ia";
        process_name_value = "pn";
        Debug::setUnitTestFlag(D_EVENT_BUFFER, Debug::DebugLevel::DEBUG);
        EXPECT_CALL(instance_awareness, getUniqueID(_)).WillRepeatedly(Return(instance_awareness_value));
        i_messaging_buffer = Singleton::Consume<I_MessagingBuffer>::from(*messaging_buffer);
        i_encryptor = Singleton::Consume<I_Encryptor>::from(encryptor);
        env.preload();
        env.init();
    }

    void
    init(bool proccess_name_value = true)
    {
        setConfiguration<string>("/tmp/event_buffer", "Event Buffer", "base folder");
        string process_path = "";
        if (proccess_name_value) process_path = "a/b/" + process_name_value;
        Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Executable Name", process_path);
        messaging_buffer->init();
    }

    ~MessagingBufferFiniTest()
    {
        i_messaging_buffer->cleanBuffer();
        Debug::setUnitTestFlag(D_EVENT_BUFFER, Debug::DebugLevel::INFO);
        Debug::setNewDefaultStdout(&cout);
        boost::filesystem::path dir_path("/tmp/event_buffer/");
        remove_all(dir_path);
        rmdir(dir_path.filename().c_str());
    }

    void
    preload()
    {
        messaging_buffer->preload();
    }

    void
    release()
    {
        messaging_buffer->fini();
        delete messaging_buffer.release();
        messaging_buffer = make_unique<MessagingBuffer>();
        i_messaging_buffer = Singleton::Consume<I_MessagingBuffer>::from(*messaging_buffer);
    }

    I_MessagingBuffer *i_messaging_buffer;

    string instance_awareness_value;
    string process_name_value;
    Encryptor encryptor;
    I_Encryptor *i_encryptor;
    StrictMock<MockTimeGet> timer;
    NiceMock<MockMainLoop> mock_mainloop;
    StrictMock<MockInstanceAwareness> instance_awareness;
    unique_ptr<MessagingBuffer> messaging_buffer;

private:
    ::Environment env;
    ConfigComponent config;
};

TEST_F(MessagingBufferFiniTest, fini)
{
    messaging_buffer->preload();
    setConfiguration<uint>(1, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();

    const size_t events_size = 101;
    vector<HTTPRequestEvent> events;
    for (size_t i = 0; i < events_size; i++) {
        events.push_back(HTTPRequestEvent("0", to_string(i), "2", to_string(i)));
        i_messaging_buffer->bufferNewRequest(events[i]);
    }

    release();

    init();
    for (size_t i = 0; i < events_size; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        ASSERT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), events[i]);
    }
}

static inline ostream &
operator<<(ostream &os, const HTTPRequestEvent &req)
{
    return os
        << "Signature: "
        << req.getSignature()
        << ", Headers: "
        << req.getHeaders()
        << ", Body "
        << req.getBody();
}

TEST_F(MessagingBufferFiniTest, hugeBufferingDoubleInit)
{
    messaging_buffer->preload();
    setConfiguration<uint>(0, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();

    vector<I_MainLoop::Routine> timer_routines;
    EXPECT_CALL(mock_mainloop, addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        _,
        _,
        _
    )).WillRepeatedly(
        WithArgs<1>(
            Invoke(
            [&](const I_MainLoop::Routine &routine)
            {
                timer_routines.push_back(routine);
                return 0;
            }
        )
    ));

    const size_t events_size = 499;
    vector<HTTPRequestEvent> events;

    for (size_t i = 0; i < events_size; i++) {
        events.push_back(HTTPRequestEvent("0", "1", "2", std::to_string(i)));
        i_messaging_buffer->bufferNewRequest(events[i]);

        // Run all pending timers
        for (auto &routine : timer_routines) routine();
        timer_routines.clear();
    }

    release();
    init();

    for (size_t i = 0; i < events_size; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        ASSERT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), events[i]);
    }
}

TEST_F(MessagingBufferFiniTest, initTempFile)
{
    messaging_buffer->preload();
    setConfiguration<uint>(0, "Event Buffer", "max buffer size in MB");
    setConfiguration<uint>(1, "Event Buffer", "max buffer files");

    EXPECT_CALL(timer, getMonotonicTime()).WillRepeatedly(
        InvokeWithoutArgs(
            [&]()
            {
                return chrono::microseconds(10000001);
            }
        )
    );
    init();
    const size_t events_size = 1;
    vector<HTTPRequestEvent> events;

    for (size_t i = 0; i < events_size; i++) {
        events.push_back(HTTPRequestEvent("0", "1", "2", "temp_file"));
        i_messaging_buffer->bufferNewRequest(events[i]);
    }

    release();
    std::ofstream outfile("/tmp/event_buffer/MDFidWZmZXJlZCBtZXNzYWdlcw==iapn.tmp");
    string tmp_file =
        "ewogICAgInRhZyI6ICJidWZmZXJlZCBtZXNzYWdlcyIsCiAgICAidmFsdWUwIjogIjAiLAo" \
        "gICAgInZhbHVlMSI6ICIxIiwKICAgICJ2YWx1ZTIiOiAiMiIsCiAgICAidmFsdWUzIjogInRlbXBfZmlsZSIKfQ==";
    outfile << tmp_file;
    outfile.close();
    init();

    for (size_t i = 0; i < events_size; i++) {
        auto req = i_messaging_buffer->peekRequest();
        i_messaging_buffer->popRequest();
        ASSERT_TRUE(req.ok());
        EXPECT_EQ(req.unpack(), events[i]);
    }
}
