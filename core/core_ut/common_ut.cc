#include "common.h"

#include <array>
#include <vector>

#include "cptest.h"
#include "customized_cereal_map.h"
#include "customized_cereal_multimap.h"

using namespace std;
using namespace cereal;

TEST(MakeSeperatedStr, array)
{
    array<int, 5> arr = { 1, 2, 3, 4, 5 };
    EXPECT_EQ(makeSeparatedStr(arr, " - "), "1 - 2 - 3 - 4 - 5");
}

TEST(MakeSeperatedStr, vector)
{
    vector<string> vec = { "aaa", "b", "c c", "dd" };
    EXPECT_EQ(makeSeparatedStr(vec, ", "), "aaa, b, c c, dd");
}

TEST(Debug, dump_printable_char)
{
    char ch = 'c';
    EXPECT_EQ(dumpHexChar(ch), string("'c'"));
}

TEST(Debug, dump_non_printable_char)
{
    char ch = 0x1B;
    EXPECT_EQ(dumpHexChar(ch), string("\\x1b"));
}

TEST(Debug, dump_hex)
{
    EXPECT_EQ(dumpHex(string("hello")), "hello");
    EXPECT_EQ(dumpHex(string("a\\b")), "a\\\\b");
    EXPECT_EQ(dumpHex(string("a\tb")), "a\\x09b");
    EXPECT_EQ(dumpHex(vector<char>({ 'w', 'o', 'r', 'l', 'd'})), "world");
    int tst_numeric[4] = {1, 10, 200, 201};
    EXPECT_EQ(dumpHex(tst_numeric), "\\x01\\x0a\\xc8\\xc9");
}

TEST(Debug, dump_real_hex)
{
    EXPECT_EQ(dumpRealHex(string("hello")), " 68 65 6c 6c 6f");
    EXPECT_EQ(dumpRealHex(string("a\\b")), " 61 5c 62");
    EXPECT_EQ(dumpRealHex(string("a\tb")), " 61 09 62");
    EXPECT_EQ(dumpRealHex(vector<char>({ 'w', 'o', 'r', 'l', 'd'})), " 77 6f 72 6c 64");
    int tst_numeric[4] = {1, 10, 200, 201};
    EXPECT_EQ(dumpRealHex(tst_numeric), " 01 0a c8 c9");
}

class Aaaa {};

class B {};

ostream & operator<<(ostream &os, const B &) { return os; }

TEST(Printable, check_if_printable)
{
    EXPECT_FALSE(IsPrintable<Aaaa>());
    EXPECT_TRUE(IsPrintable<B>());
    EXPECT_TRUE(IsPrintable<int>());
    EXPECT_TRUE(IsPrintable<string>());
}

class TestCerealMap : public testing::Test
{
public:
    template<typename Type>
    string
    serializeMap(const map<string, Type> &test_map, const string &map_key)
    {
        std::stringstream out;
        {
            cereal::JSONOutputArchive out_ar(out);
            out_ar(cereal::make_nvp(map_key, test_map));
        }
        return out.str();
    }

    template<typename Type>
    map<string, Type>
    deserializeMap(const string &map_text, const string &map_key)
    {
        map<string, Type> ret_value;
        std::stringstream in;
        in << map_text;
        {
            cereal::JSONInputArchive in_ar(in);
            in_ar(cereal::make_nvp(map_key, ret_value));
        }
        return ret_value;
    }
};

TEST_F(TestCerealMap, serialize)
{
    map<string, string> strings_map = {{"fi", "fa"}, {"fo", "fam"}, {"bisli", "bamba"}};
    map<string, int> ints_map = {{"4", 2}, {"42", 420}};
    using strings = vector<string>;
    map<string, strings> strings_vectors_map = {{"1", strings({"2", "3"})}};
    EXPECT_EQ(
        serializeMap<string>(strings_map, "strings_map"),
        "{\n"
        "    \"strings_map\": {\n"
        "        \"bisli\": \"bamba\",\n"
        "        \"fi\": \"fa\",\n"
        "        \"fo\": \"fam\"\n"
        "    }\n"
        "}"

    );
    EXPECT_EQ(
        serializeMap<int>(ints_map, "ints_map"),
        "{\n"
        "    \"ints_map\": {\n"
        "        \"4\": 2,\n"
        "        \"42\": 420\n"
        "    }\n"
        "}"

    );
    EXPECT_EQ(
        serializeMap<strings>(strings_vectors_map, "strings_vectors_map"),
        "{\n"
        "    \"strings_vectors_map\": {\n"
        "        \"1\": [\n"
        "            \"2\",\n"
        "            \"3\"\n"
        "        ]\n"
        "    }\n"
        "}"
    );
}

TEST_F(TestCerealMap, desirialize)
{
    string map_str = "{\"bool_map\" :{\"true\": true, \"false\": false }}";
    map<string, bool> expected_bools_map({{"true", true}, {"false", false}});
    EXPECT_EQ(deserializeMap<bool>(map_str, "bool_map"), expected_bools_map);

    map_str = "{\"string_map\" :{\"str\": \"str\", \"char *\": \"char *\" }}";
    map<string, string> expected_string_map({{"str", "str"}, {"char *", "char *"}});
    EXPECT_EQ(deserializeMap<string>(map_str, "string_map"), expected_string_map);

    map_str = "{\"strings_vectors_map\" :{\"hello\": [\"world\", \"universe\"], \"hi\": [\"space\"] }}";
    using strings = vector<string>;

    map<string, strings> expected_strings_vectors_map(
        {{"hello", strings({"world", "universe"})},
        {"hi", strings({"space"})}}
    );
    EXPECT_EQ(deserializeMap<strings>(map_str, "strings_vectors_map"), expected_strings_vectors_map);
}

TEST(TestCerealMultimap, regularStringMap)
{
    SerializableMultiMap<string> m;

    string data_str =
        "{\n"
        "  \"multimap\": {\n"
        "    \"user\": \"omry\"\n"
        "  }\n"
        "}";

    stringstream is;
    is << data_str;
    JSONInputArchive ar(is);
    ar(make_nvp("multimap", m));

    EXPECT_EQ(m.getMap<string>()["user"], "omry");
}

TEST(TestCerealMultimap, mixedPrimitivesMap)
{
    SerializableMultiMap<string, int, bool> m;

    string data_str =
        "{\n"
        "  \"multimap\": {\n"
        "    \"user\": \"omry\",\n"
        "    \"number\": 14,\n"
        "    \"king of cpp\": true\n"
        "  }\n"
        "}";

    stringstream is;
    is << data_str;
    JSONInputArchive ar(is);
    ar(make_nvp("multimap", m));

    EXPECT_EQ(m.getMap<string>()["user"], "omry");
    EXPECT_EQ(m.getMap<int>()["number"], 14);
    EXPECT_EQ(m.getMap<bool>()["king of cpp"], true);
}

TEST(TestCerealMultimap, mixedPrimitivesAndObjectsMap)
{
    SerializableMultiMap<string, int, bool, vector<string>> m;

    string data_str =
        "{\n"
        "  \"multimap\": {\n"
        "    \"user\": \"omry\",\n"
        "    \"number\": 14,\n"
        "    \"king of cpp\": true,\n"
        "    \"friends\": [\n"
        "      \"Max\",\n"
        "      \"David\",\n"
        "      \"Daniel\",\n"
        "      \"Oren\",\n"
        "      \"Roi\",\n"
        "      \"Moaad\"\n"
        "    ]\n"
        "  }\n"
        "}";

    stringstream is;
    is << data_str;
    JSONInputArchive ar(is);
    ar(make_nvp("multimap", m));

    EXPECT_EQ(m.getMap<string>()["user"], "omry");
    EXPECT_EQ(m.getMap<int>()["number"], 14);
    EXPECT_EQ(m.getMap<bool>()["king of cpp"], true);
    EXPECT_EQ(m.getMap<vector<string>>()["friends"].front(), "Max");
}
