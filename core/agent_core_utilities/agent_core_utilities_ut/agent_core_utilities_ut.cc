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

USE_DEBUG_FLAG(D_INFRA_UTILS);

auto contexts = make_pair(std::vector<Context *>(), false);

class AgentCoreUtilUT : public Test
{
public:
    AgentCoreUtilUT()
    {
        Debug::setUnitTestFlag(D_INFRA_UTILS, Debug::DebugLevel::TRACE);
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
    const vector<string> lines_b{"i am a line 2 in the text file", "i am iron man 2", "hello again"};
    CPTestTempfile test_file(lines);
    CPTestTempfile test_file_b(lines_b);
    ASSERT_TRUE(NGEN::Filesystem::exists(test_file.fname));
    ASSERT_TRUE(NGEN::Filesystem::exists(test_file_b.fname));

    string output_orig = test_file.readFile();
    string new_path = test_file.fname + ".new";
    ASSERT_TRUE(NGEN::Filesystem::copyFile(test_file.fname, new_path, false));
    ASSERT_TRUE(NGEN::Filesystem::exists(new_path));
    ASSERT_FALSE(NGEN::Filesystem::copyFile(test_file.fname, new_path, false));
    ASSERT_TRUE(NGEN::Filesystem::copyFile(test_file.fname, new_path, true));
    ASSERT_TRUE(NGEN::Filesystem::copyFile(test_file.fname, test_file_b.fname, true));
    string output_new;
    {
        ifstream new_file_stream(new_path);
        ASSERT_TRUE(new_file_stream.good());
        stringstream buffer;
        buffer << new_file_stream.rdbuf();
        output_new = buffer.str();
    }

    string output_test_b;
    ifstream new_file_stream(test_file_b.fname);
    ASSERT_TRUE(new_file_stream.good());
    stringstream buffer;
    buffer << new_file_stream.rdbuf();
    output_test_b = buffer.str();

    EXPECT_EQ(output_orig, output_new);
    EXPECT_EQ(output_orig, output_test_b);
    EXPECT_THAT(output_new, HasSubstr("i am a line in the text file"));
    EXPECT_THAT(output_new, HasSubstr("i am iron man"));
    EXPECT_TRUE(NGEN::Filesystem::deleteFile(test_file.fname));
    EXPECT_TRUE(NGEN::Filesystem::deleteFile(new_path));
    EXPECT_TRUE(NGEN::Filesystem::deleteFile(test_file_b.fname));
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

TEST_F(AgentCoreUtilUT, copyDirectoryTest)
{
    string sourceDir = cptestFnameInExeDir("sourceDir1");
    string destDir = cptestFnameInExeDir("destDir1");
    cout << "sourceDir: " << sourceDir << endl;
    NGEN::Filesystem::makeDir(sourceDir);
    NGEN::Filesystem::makeDir(sourceDir + "/subdir1");
    NGEN::Filesystem::makeDir(sourceDir + "/subdir2");
    NGEN::Filesystem::makeDir(destDir);

    ofstream file_1(sourceDir + "/file1.txt");
    ASSERT_TRUE(file_1.is_open());
    file_1 << "File 1 content";
    file_1.close();
    ofstream file_2(sourceDir + "/subdir1/file2.txt");
    ASSERT_TRUE(file_2.is_open());
    file_2 << "File 2 content";
    file_2.close();
    ofstream file_3(sourceDir + "/subdir2/file3.txt");
    ASSERT_TRUE(file_3.is_open());
    file_3 << "File 3 content";
    file_3.close();

    ASSERT_TRUE(NGEN::Filesystem::copyDirectory(sourceDir, destDir));

    EXPECT_TRUE(NGEN::Filesystem::exists(destDir));
    EXPECT_TRUE(NGEN::Filesystem::exists(destDir + "/file1.txt"));
    EXPECT_TRUE(NGEN::Filesystem::exists(destDir + "/subdir1/file2.txt"));
    EXPECT_TRUE(NGEN::Filesystem::exists(destDir + "/subdir2/file3.txt"));

    ifstream file1(destDir + "/file1.txt");
    string content1((istreambuf_iterator<char>(file1)), istreambuf_iterator<char>());
    EXPECT_EQ(content1, "File 1 content");
    file1.close();

    ifstream file2(destDir + "/subdir1/file2.txt");
    string content2((istreambuf_iterator<char>(file2)), istreambuf_iterator<char>());
    EXPECT_EQ(content2, "File 2 content");
    file2.close();

    ifstream file3(destDir + "/subdir2/file3.txt");
    string content3((istreambuf_iterator<char>(file3)), istreambuf_iterator<char>());
    EXPECT_EQ(content3, "File 3 content");
    file3.close();

    NGEN::Filesystem::deleteDirectory(sourceDir + "/subdir1", true);
    NGEN::Filesystem::deleteDirectory(sourceDir + "/subdir2", true);
    NGEN::Filesystem::deleteDirectory(sourceDir, true);
    NGEN::Filesystem::deleteDirectory(destDir + "/subdir1", true);
    NGEN::Filesystem::deleteDirectory(destDir + "/subdir2", true);
    NGEN::Filesystem::deleteDirectory(destDir, true);
}

TEST_F(AgentCoreUtilUT, removeTrailingWhitespacesTest)
{
    string str_with_trailing_whitespace = "str_with_trailing_whitespace\n\n\n\r    \n\n\r";
    EXPECT_EQ(NGEN::Strings::removeTrailingWhitespaces(str_with_trailing_whitespace), "str_with_trailing_whitespace");
}

TEST_F(AgentCoreUtilUT, removeLeadingWhitespacesTest)
{
    string str_with_leading_whitespace = "\n\n\n\r    \n\n\rstr_with_leading_whitespace";
    EXPECT_EQ(NGEN::Strings::removeLeadingWhitespaces(str_with_leading_whitespace), "str_with_leading_whitespace");
}

TEST_F(AgentCoreUtilUT, trimTest)
{
    string str_with_leading_and_trailing_whitespace = "\n\n \r  \rstr_with_whitespace\n\r \n\n\r";
    EXPECT_EQ(NGEN::Strings::trim(str_with_leading_and_trailing_whitespace), "str_with_whitespace");
}

TEST_F(AgentCoreUtilUT, toLowerTest)
{
    string str = "ThIS Is A 123 TEsT StRiNG";
    EXPECT_EQ(NGEN::Strings::toLower(str), "this is a 123 test string");
}

TEST_F(AgentCoreUtilUT, resolveFullPathTest)
{
    string working_dir = cptestFnameInExeDir("");
    ofstream file(working_dir + "test.txt");
    ASSERT_TRUE(file.is_open());
    file.close();
    string relative_path = "test.txt";
    string full_path = NGEN::Filesystem::resolveFullPath(relative_path);
    EXPECT_EQ(full_path, working_dir + "test.txt");
    ASSERT_TRUE(NGEN::Filesystem::deleteFile(working_dir + "test.txt"));
}

TEST_F(AgentCoreUtilUT, regexReplaceTest)
{
    struct TestCase {
        std::string input;
        std::string expected;
    };

    std::vector<TestCase> test_cases = {
        {"my?invalid//:filename*test.txt", "my_invalid_filename_test.txt"},
        {"hello///world", "hello_world"},
        {"file@@name..txt", "file_name..txt"},
        {"file--name", "file--name"},
        {"some@@@file!!name.txt", "some_file_name.txt"},
        {"https://some_file_name.txt", "https_some_file_name.txt"},
        {"spaces in filename.txt", "spaces_in_filename.txt"},
        {"trailing-dash-", "trailing-dash-"},
        {"trailing.dot.", "trailing.dot."},
        {"file name with (parens).txt", "file_name_with_parens_.txt"},
        {"$pecial#Chars&here.txt", "_pecial_Chars_here.txt"},
        {"___leading_underscores", "___leading_underscores"},
        {"<<<<weird>>>filename", "_weird_filename"},
        {"double..dots...txt", "double..dots...txt"},
        {"a:b|c*d?e<f>g/h.txt", "a_b_c_d_e_f_g_h.txt"},
        {"/leading/slash", "_leading_slash"},
        {"back\\slash\\file", "back_slash_file"},
        {"file.with..multiple.dots.txt", "file.with..multiple.dots.txt"},
        {"CAPITAL&LETTERS^HERE", "CAPITAL_LETTERS_HERE"},
        {"123_456-789.ok", "123_456-789.ok"},
        {"__", "__"},
        {"*.*", "_._"}
    };

    boost::regex regex("[^\\w.-]+"); // Matches one or more non-word, non-dot, non-hyphen characters

    for (const auto& testCase : test_cases) {
        std::string replaced = NGEN::Regex::regexReplace(__FILE__, __LINE__, testCase.input, regex, "_");
        EXPECT_EQ(replaced, testCase.expected);
    }
}
