#include <string>

#include "cptest.h"
#include "pm_hook.h"

using namespace std;
using namespace testing;

ostream & operator<<(ostream &os, const PMPattern &) { return os; }

static void
push_pat(set<PMPattern> &pats, const string &hex_pat)
{
    auto pat = PMHook::lineToPattern(hex_pat.c_str());
    EXPECT_TRUE(pat.ok()) << pat.getErr();
    pats.insert(*pat);
}

static set<PMPattern>
getPatternSet(const string &pattern)
{
    set<PMPattern> res;
    push_pat(res, pattern);
    return res;
}

template <typename ... Patterns>
static set<PMPattern>
getPatternSet(const string &pattern, Patterns ...more_patterns)
{
    auto res = getPatternSet(more_patterns...);
    push_pat(res, pattern);
    return res;
}

static set<PMPattern>
prepare_scan_and_compare(const set<PMPattern> &pats, const string &buf)
{
    PMHook pm;
    EXPECT_TRUE(pm.prepare(pats).ok());

    return pm.scanBuf(Buffer(buf));
}

// This is a helper function for the trivial tests. buf is NULL terminated, and the NULL is NOT passed to the PM.
static set<PMPattern>
common_scan_test_single_pat(const string &hex_pat, const string &buf)
{
    set<PMPattern> pats;
    push_pat(pats, hex_pat);

    return prepare_scan_and_compare(pats, buf);
}

TEST(pm_scan, zero_buf_len)
{
    EXPECT_EQ(common_scan_test_single_pat("ABCD", ""), set<PMPattern>());
}

TEST(pm_scan, basic)
{
    EXPECT_EQ(common_scan_test_single_pat("ABCD", "ABCD ABCD AB AB ABC ABCD"), getPatternSet("ABCD"));
}

TEST(pm_scan, with_start_flag)
{
    EXPECT_EQ(common_scan_test_single_pat("^ABCD", "ABCD ABCD AB AB ABC AAAAAAA"), getPatternSet("^ABCD"));
}

TEST(pm_scan, with_start_flag_short_buf)
{
    EXPECT_EQ(common_scan_test_single_pat("^A", "ABC"), getPatternSet("^A"));
}

TEST(pm_scan, with_end_flag)
{
    EXPECT_EQ(common_scan_test_single_pat("ABCD$",  "KKKK ABCD ABCD ABCD"), getPatternSet("ABCD$"));
}

TEST(pm_scan, nomatch)
{
    EXPECT_EQ(common_scan_test_single_pat("AAA", "AA"), set<PMPattern>());
}

TEST(pm_scan, exact_match)
{
    EXPECT_EQ(common_scan_test_single_pat("AAA", "AAA"), getPatternSet("AAA"));
}

TEST(pm_scan, overlap_in_buf)
{
    EXPECT_EQ(common_scan_test_single_pat("AAA", "AAAA"), getPatternSet("AAA"));
}

TEST(pm_scan, with_begin_and_end_flag_no_match)
{
    EXPECT_EQ(common_scan_test_single_pat("^AAA$", "AAAA"), set<PMPattern>());
}

TEST(pm_scan, with_begin_and_end_flag_match)
{
    EXPECT_EQ(common_scan_test_single_pat("^ABC$", "ABC"), getPatternSet("^ABC$"));
}

TEST(pm_scan, many_matches)
{
    EXPECT_EQ(
        common_scan_test_single_pat(
            "AAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ),
        getPatternSet("AAA")
    );
}

TEST(pm_scan, long_pattern)
{
    string long_str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";

    EXPECT_EQ(common_scan_test_single_pat(long_str, ".-= " + long_str + " =-."), getPatternSet(long_str));
}


TEST(pm_scan, very_long_pattern)
{
    string abc = "abcdefghijklmnopqrstuvwxyz";
    string very_long_str;
    // We choose 3000 repeatitions, becuase this gives a total of 78K chars. If there's
    // some unsigned short used internally ,we hope to overflow it.
    for (int i = 0; i<3000; i++) {
        very_long_str     += abc;
    }
    string pattern = very_long_str;

    // What if the PM internally truncated our very long pattern?
    // Because it is cyclic, we might not catch it in the line above.
    // So we ask it to find the pattern in a buffer containing almost the whole pattern, but not all of it.
    string truncated_begin(pattern, 1, pattern.size() - 1);
    string truncated_end(pattern, 0, pattern.size() - 1);

    // We put a sepearator between them (which doesn't any char from the pattern), so there's no additional
    // matches on buf_to_scan
    const string seperator_str = "1234";
    auto buf_to_scan = seperator_str+very_long_str+seperator_str+truncated_end+seperator_str+truncated_begin;

    EXPECT_EQ(common_scan_test_single_pat(pattern, buf_to_scan), getPatternSet(pattern));
}

TEST(pm_scan, multiple_pats)
{
    string buf = "KKKK ABCD AB AB ABC ABCD DCBA";
    set<PMPattern> pats;
    push_pat(pats, "ABCD");
    push_pat(pats, "DCBA");
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("ABCD", "DCBA"));
}

TEST(pm_scan, multiple_pats_with_overlap)
{
    string buf = "KKKK ABCDCBA";
    set<PMPattern> pats;
    push_pat(pats, "ABCD");
    push_pat(pats, "DCBA");
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("ABCD", "DCBA"));
}


TEST(pm_scan, multiple_long_pats_with_overlap)
{
    string buf = "KKKK ABCDEFGHIJKLMNOPQRSTUVWXYZ ABCDEFGHIJKLMNOPQRSTUVWXYZ!";
    set<PMPattern> pats;
    push_pat(pats, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    push_pat(pats, "ABCDEFGHIJKLMNOPQRSTUVWXYZ!");
    EXPECT_EQ(
        prepare_scan_and_compare(pats, buf),
        getPatternSet("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCDEFGHIJKLMNOPQRSTUVWXYZ!")
    );
}

TEST(pm_scan, many_pats)
{
    string buf = "KKKK ABC1 asdasdf";
    set<PMPattern> pats;
    push_pat(pats, "ABC1");
    push_pat(pats, "ABC2");
    push_pat(pats, "ABC3");
    push_pat(pats, "ABC4");
    push_pat(pats, "ABC5");
    push_pat(pats, "ABC6");
    push_pat(pats, "ABC7");
    push_pat(pats, "ABC8");
    push_pat(pats, "asdasdf");
    push_pat(pats, "zzxxdda");
    push_pat(pats, "d1tt6335!!");
    push_pat(pats, "zxcqwwrqwer!!");
    push_pat(pats, "!sdazsd!");
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("ABC1", "asdasdf"));
}

TEST(pm_scan, a_lot_of_pats)
{
    string buf = "KKKK some_100_pat some_1000_pat";
    set<PMPattern> pats;
    for (uint i = 0; i<3000; i++) {
        char temp_buf[100];
        snprintf(temp_buf, sizeof(temp_buf), "some_%u_pat", i);
        push_pat(pats, temp_buf);
    }
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("some_100_pat", "some_1000_pat"));
}

TEST(pm_scan, long_pat_prefix_followed_by_many_branches)
{
    string buf = "some_long_prefix_a_pat some_long_prefix_z_pat some_long_prefix_a_pat";
    set<PMPattern> pats;
    for (u_char c = 'a'; c<='z';  c++) {
        char temp_buf[100];
        snprintf(temp_buf, sizeof(temp_buf), "some_long_prefix_%c_pat", c);
        push_pat(pats, temp_buf);
    }
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("some_long_prefix_a_pat", "some_long_prefix_z_pat"));
}

TEST(pm_scan, identical_pats)
{
    string buf = "KKKK 123 ---";
    set<PMPattern> pats;
    push_pat(pats, "123");
    push_pat(pats, "123");
    EXPECT_EQ(prepare_scan_and_compare(pats, buf), getPatternSet("123"));
}

TEST(pm_scan, multiple_scans_using_same_pm)
{
    Buffer buf1("ABC 123 ABC");
    Buffer buf2("^^^%%%!! 123 ABC");
    set<PMPattern> pats;
    push_pat(pats, "ABC");
    push_pat(pats, "%%%");
    PMHook pm;
    ASSERT_TRUE(pm.prepare(pats).ok());

    auto expected_matches1 = getPatternSet("ABC");
    auto expected_matches2 = getPatternSet("ABC", "%%%");

    EXPECT_EQ(pm.scanBuf(buf1), expected_matches1);
    EXPECT_EQ(pm.scanBuf(buf2), expected_matches2);
    EXPECT_EQ(pm.scanBuf(buf1), expected_matches1);
}

TEST(pm_scan, scan_with_offsets)
{
    Buffer buf1("ABC");
    Buffer buf2("EFG");
    Buffer buf3 = buf1 + buf2 + buf1;
    set<PMPattern> pats;
    push_pat(pats, "ABC");
    PMHook pm;
    ASSERT_TRUE(pm.prepare(pats).ok());

    set<pair<uint, PMPattern>> res;
    res.emplace(2, PMHook::lineToPattern("ABC").unpackMove());
    res.emplace(8, PMHook::lineToPattern("ABC").unpackMove());
    EXPECT_THAT(pm.scanBufWithOffset(buf3), ContainerEq(res));
}

TEST(pm_scan, null_buf)
{
    set<PMPattern> pats;
    push_pat(pats, "ABCD");
    PMHook pm;
    ASSERT_TRUE(pm.prepare(pats).ok());
    EXPECT_EQ(pm.scanBuf(Buffer("")), set<PMPattern>());
}

TEST(pm_scan, exit_on_no_prepare)
{
    Buffer buf("blah");
    cptestPrepareToDie();
    PMHook pm;
    EXPECT_DEATH(pm.scanBuf(buf), "Unusable Pattern Matcher");
}

TEST(pm_scan, prepare_fail_on_no_pats)
{
    set<PMPattern> pats;
    PMHook pm;
    EXPECT_FALSE(pm.prepare(pats).ok());
}

TEST(pm_scan, pm_offsets_test_multiple_matches)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("he", false, false));
    initPatts.insert(PMPattern("ex", false, false));
    initPatts.insert(PMPattern("hex", false, false, 2));
    initPatts.insert(PMPattern("(", false, false, 5));
    initPatts.insert(PMPattern(")", false, false, 7));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("hex()");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {1, {"he", false, false, 0}},
        {2, {"ex", false, false, 0}},
        {2, {"hex", false, false, 2}},
        {3, {"(", false, false, 5}},
        {4, {")", false, false, 7}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_one_char_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("/", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("/");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {0, {"/", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_one_char_at_end_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("/", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("abc/");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {3, {"/", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_one_char_at_start_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("/", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("/abc");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {0, {"/", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_word_full_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("abc", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("abc");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {2, {"abc", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_word_at_start_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("application", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("application/x-www-form-urlencoded");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {10, {"application", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_word_at_end_match)
{
    PMHook pm;
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("x-www-form-urlencoded", false, false));

    ASSERT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("application/x-www-form-urlencoded");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {32, {"x-www-form-urlencoded", false, false, 0}}
    };

    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_test_pat_getIndex_method)
{
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("ABC", false, false)); // initialized with the default index 0
    initPatts.insert(PMPattern("ABCD", false, false, 4));
    initPatts.insert(PMPattern("CDE", false, false, 7));
    PMHook pm;
    EXPECT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("12345ABCDEF5678");
    std::set<std::pair<uint, PMPattern>> results = pm.scanBufWithOffset(buf);

    std::set<std::pair<uint, PMPattern>> expected{
        {7, {"ABC", false, false, 0}},
        {8, {"ABCD", false, false, 4}},
        {9, {"CDE", false, false, 7}}
    };
    EXPECT_EQ(results, expected);
}

TEST(pm_scan, pm_offsets_lambda_test_pat_getIndex_method)
{
    set<PMPattern> initPatts;
    initPatts.insert(PMPattern("ABC", false, false)); // initialized with the default index 0
    initPatts.insert(PMPattern("ABCD", false, false, 4));
    initPatts.insert(PMPattern("CDE", false, false, 7));
    PMHook pm;
    EXPECT_TRUE(pm.prepare(initPatts).ok());

    Buffer buf("12345ABCDEF5678");
    std::vector<std::pair<u_int, PMPattern>> results;
    pm.scanBufWithOffsetLambda(buf, [&] (uint offset, const PMPattern &pat) { results.emplace_back(offset, pat); });

    std::vector<std::pair<uint, PMPattern>> expected{
        {7, {"ABC", false, false, 0}},
        {8, {"ABCD", false, false, 4}},
        {9, {"CDE", false, false, 7}}
    };

    EXPECT_EQ(results, expected);
}
