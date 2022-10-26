#include <string>
#include <fstream>

#include "cptest.h"
#include "pm_hook.h"

using namespace std;

static void
pm_pat_simple_pat(
    const std::string &hex_line,
    const std::string &line,
    bool expected_match_at_start,
    bool expected_match_at_end)
{
    PMPattern pat;
    auto res = PMHook::lineToPattern(hex_line.c_str());
    EXPECT_TRUE(res.ok()) << res.getErr();
    pat = *res;
    EXPECT_EQ(pat.isStartMatch(), expected_match_at_start);
    EXPECT_EQ(pat.isEndMatch(), expected_match_at_end);
    ASSERT_EQ(pat.size(), line.size());
    EXPECT_EQ(memcmp((const char *)pat.data(), line.c_str(), line.size()), 0);
}

static void
pm_pat_bad_pat(const std::string &bad_hex_line)
{
    EXPECT_FALSE(PMHook::lineToPattern(bad_hex_line).ok());
}

TEST(pm_pat, basic)
{
    pm_pat_simple_pat("ABCDxyz", "ABCDxyz", false, false);
}

TEST(pm_pat, pat_with_begin)
{
    pm_pat_simple_pat("^ABCD", "ABCD", true, false);
}

TEST(pm_pat, pat_with_end)
{
    pm_pat_simple_pat("ABCD$", "ABCD", false, true);
}

TEST(pm_pat, pat_with_begin_end)
{
    pm_pat_simple_pat("^ABCD$", "ABCD", true, true);
}

TEST(pm_pat, pat_with_all_chars)
{
    pm_pat_simple_pat("ABCDEFGHIJKLMNOPJKLMNO", "ABCDEFGHIJKLMNOPJKLMNO", false, false);
}

TEST(pm_pat, empty_pat_with_begin_end)
{
    pm_pat_bad_pat("^$");
}

TEST(pm_pat, empty_pat)
{
    pm_pat_bad_pat("");
}

TEST(pm_pat, chars_above_127)
{
    static const vector<u_char> buf = { 0x80, 0x96, 0xaa, 0xff };
    PMPattern pat;
    auto rc = PMHook::lineToPattern(string(buf.begin(), buf.end()));
    EXPECT_TRUE(rc.ok()) << rc.getErr();
    pat = *rc;
    EXPECT_FALSE(pat.isStartMatch());
    EXPECT_FALSE(pat.isEndMatch());
    ASSERT_EQ(pat.size(), buf.size());
    EXPECT_EQ(memcmp(pat.data(), buf.data(), buf.size()), 0);
}
