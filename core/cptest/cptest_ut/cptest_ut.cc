#include "cptest.h"
#include <fstream>

using namespace std;
using namespace testing;

TEST(CPTest, PrepareToDie)
{
    cptestPrepareToDie();
    auto die = []() {
        dbgAssert(false) << "You killed my father";
    };
    EXPECT_DEATH(die(), "You killed my father");
}

TEST(Hex, parse)
{
    auto v = cptestParseHex("0000: 01 02 03");
    EXPECT_THAT(v, ElementsAre(1, 2, 3));
}

TEST(Hex, generate)
{
    auto hex = cptestGenerateHex(vector<u_char>{'h', 'e', 'l', 'l', 'o'}, false);
    EXPECT_THAT(hex, HasSubstr("68 65 6c 6c 6f"));            // hello in hex
}

TEST(Hex, generateWithOffset)
{
    auto hex = cptestGenerateHex(vector<u_char>{'h', 'e', 'l', 'l', 'o'}, true);
    EXPECT_THAT(hex, StartsWith("0000:"));
    EXPECT_THAT(hex, HasSubstr("68 65 6c 6c 6f"));            // hello in hex
}

TEST(File, tempEmpty)
{
    CPTestTempfile t;
    ifstream ifs(t.fname, ifstream::in);
    ostringstream os;
    os << ifs.rdbuf();
    EXPECT_EQ("", os.str());
}

TEST(File, tempNotEmpty)
{
    vector<string> lines = {
        "hello",
        "world"
    };
    CPTestTempfile t(lines);
    ifstream ifs(t.fname, ifstream::in);
    ostringstream os;
    os << ifs.rdbuf();
    EXPECT_EQ("hello\nworld\n", os.str());
}

TEST(File, pathInExeDir)
{
    string p = cptestFnameInExeDir("try.txt");
    EXPECT_THAT(p, EndsWith("/try.txt"));
}

TEST(File, pathInSrcDir)
{
    string p = cptestFnameInSrcDir("try.txt");
    EXPECT_THAT(p, EndsWith("/core/cptest/cptest_ut/try.txt"));
}
