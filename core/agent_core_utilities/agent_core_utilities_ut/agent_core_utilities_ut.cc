#include "agent_core_utilities.h"
#include "shell_cmd.h"
#include "cptest.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "mock/mock_environment.h"
#include "config_component.h"
#include "time_proxy.h"

using namespace std;
using namespace testing;

auto contexts = make_pair(std::vector<Context *>(), false);

class AgentCoreUtilUT : public Test
{
public:
    AgentCoreUtilUT()
    {
        ON_CALL(mock_env, getActiveContexts()).WillByDefault(ReturnPointee(&contexts));
    }

    ~AgentCoreUtilUT()
    {
    }

private:
    NiceMock<MockEnvironment> mock_env;
    TimeProxyComponent time_get;
    NiceMock<MockMainLoop> mock_mainloop;
    ConfigComponent config;
    chrono::milliseconds mocked_cur_time;
};

TEST_F(AgentCoreUtilUT, filesTest)
{
    EXPECT_FALSE(NGEN::Filesystem::exists("/i/am/not/a/real/path"));

    const vector<string> lines{"i am a line in the text file", "i am iron man"};
    CPTestTempfile test_file(lines);
    ASSERT_TRUE(NGEN::Filesystem::exists(test_file.fname));

    string output_orig = test_file.readFile();
    string new_path = test_file.fname + ".new";
    ASSERT_TRUE(NGEN::Filesystem::copyFile(test_file.fname, new_path, false));
    ASSERT_TRUE(NGEN::Filesystem::exists(new_path));
    ASSERT_FALSE(NGEN::Filesystem::copyFile(test_file.fname, new_path, false));
    ASSERT_TRUE(NGEN::Filesystem::copyFile(test_file.fname, new_path, true));
    string output_new;
    {
        ifstream new_file_stream(new_path);
        ASSERT_TRUE(new_file_stream.good());
        stringstream buffer;
        buffer << new_file_stream.rdbuf();
        output_new = buffer.str();
    }

    EXPECT_EQ(output_orig, output_new);
    EXPECT_THAT(output_new, HasSubstr("i am a line in the text file"));
    EXPECT_THAT(output_new, HasSubstr("i am iron man"));
    EXPECT_TRUE(NGEN::Filesystem::deleteFile(test_file.fname));
    EXPECT_TRUE(NGEN::Filesystem::deleteFile(new_path));
    EXPECT_FALSE(NGEN::Filesystem::exists(test_file.fname));
    EXPECT_FALSE(NGEN::Filesystem::exists(new_path));
}

TEST_F(AgentCoreUtilUT, directoryTest)
{
    EXPECT_FALSE(NGEN::Filesystem::exists("/tmp/1/2/3/4"));
    EXPECT_FALSE(NGEN::Filesystem::makeDir("/tmp/1/2/3/4"));
    EXPECT_TRUE(NGEN::Filesystem::makeDir("/tmp/1"));
    EXPECT_TRUE(NGEN::Filesystem::exists("/tmp/1"));
    EXPECT_TRUE(NGEN::Filesystem::makeDirRecursive("/tmp/1/2/3/4"));
    EXPECT_TRUE(NGEN::Filesystem::exists("/tmp/1/2/3/4"));
    EXPECT_FALSE(NGEN::Filesystem::deleteDirectory("/tmp/1"));
    EXPECT_TRUE(NGEN::Filesystem::deleteDirectory("/tmp/1/2/3/4"));
    EXPECT_TRUE(NGEN::Filesystem::deleteDirectory("/tmp/1", true));
    EXPECT_FALSE(NGEN::Filesystem::exists("/tmp/1"));
}

TEST_F(AgentCoreUtilUT, printTest)
{
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(0), "0 Bytes");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(20), "20 Bytes");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000), "0.98 KB");
    uint64_t kilobyte = 1024;
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(kilobyte), "1.00 KB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*kilobyte - 1), "1000.00 KB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*kilobyte), "0.98 MB");
    uint64_t megabyte = kilobyte * kilobyte;
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(megabyte), "1.00 MB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*megabyte - kilobyte), "1000.00 MB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*megabyte), "0.98 GB");
    uint64_t gigabyte  = megabyte * kilobyte;
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(gigabyte), "1.00 GB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*gigabyte - megabyte), "1000.00 GB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1000*gigabyte), "1000.00 GB");
    EXPECT_EQ(NGEN::Filesystem::convertToHumanReadable(1024*gigabyte), "1024.00 GB");
}

TEST_F(AgentCoreUtilUT, fileBasenameTest)
{
    EXPECT_EQ(NGEN::Filesystem::getFileName("/test/base/file/name"), "name");
}

TEST_F(AgentCoreUtilUT, isDirectoryTest)
{
    mkdir("./test", 0400);
    EXPECT_EQ(NGEN::Filesystem::isDirectory("/test/base/file/name"), false);
    EXPECT_EQ(NGEN::Filesystem::isDirectory("./test"), true);
}

TEST_F(AgentCoreUtilUT, removeTrailingWhitespacesTest)
{
    string str_with_trailing_whitespace = "str_with_trailing_whitespace\n\n\n\r    \n\n\r";
    EXPECT_EQ(NGEN::Strings::removeTrailingWhitespaces(str_with_trailing_whitespace), "str_with_trailing_whitespace");
}
